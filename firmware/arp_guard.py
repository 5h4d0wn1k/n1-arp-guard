#!/usr/bin/env python3
"""
N1 - ARP Guard
Pure-stdlib ARP spoofing detector with real packet-layer construction/parsing.

The core (packet build/parse + spoof-decider state machine) runs fully
unprivileged and deterministically. Live sniffing on a real interface
(which needs raw sockets / root) is gated behind --live/--iface.

All sample addresses below are documentation-only (RFC 5737 TEST-NET).
"""
import argparse
import os
import signal
import socket
import struct
import sys
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import ARP, Ether, sniff  # type: ignore
    _SCAPY = True
except ImportError:
    _SCAPY = False

ETH_P_ARP = 0x0806
ARP_HRD_ETHERNET = 1
ARP_PROT_IPV4 = 0x0800
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2
BROADCAST_MAC = b'\xff' * 6
ZERO_MAC = b'\x00' * 6


def mac_to_bytes(mac):
    """Convert 'AA:BB:CC:DD:EE:FF' (any separator) to 6 bytes."""
    return bytes.fromhex(''.join(c for c in mac if c in '0123456789abcdefABCDEF'))


def mac_to_str(b):
    return ':'.join('%02x' % x for x in b)


def ip_to_bytes(ip):
    return socket.inet_aton(ip)


def ip_to_str(b):
    return socket.inet_ntoa(b)


class ARPFrame:
    """Build and parse raw Ethernet+ARP frames."""

    def __init__(self, op, sha, spa, tha, tpa,
                 eth_src=None, eth_dst=None):
        self.op = op
        self.sha = mac_to_bytes(sha) if isinstance(sha, str) else sha
        self.spa = ip_to_bytes(spa) if isinstance(spa, str) else spa
        self.tha = mac_to_bytes(tha) if isinstance(tha, str) else tha
        self.tpa = ip_to_bytes(tpa) if isinstance(tpa, str) else tpa
        self.eth_src = (mac_to_bytes(eth_src) if eth_src and isinstance(eth_src, str)
                        else eth_src or self.sha)
        self.eth_dst = (mac_to_bytes(eth_dst) if eth_dst and isinstance(eth_dst, str)
                        else eth_dst or BROADCAST_MAC)

    @classmethod
    def request(cls, sha, spa, tpa, eth_dst=BROADCAST_MAC, eth_src=None):
        return cls(ARP_OP_REQUEST, sha, spa, ZERO_MAC, tpa,
                   eth_src=eth_src, eth_dst=eth_dst)

    @classmethod
    def reply(cls, sha, spa, tha, tpa, eth_src=None, eth_dst=None):
        return cls(ARP_OP_REPLY, sha, spa, tha, tpa,
                   eth_src=eth_src, eth_dst=eth_dst)

    def build(self):
        eth = struct.pack('!6s6sH', self.eth_dst, self.eth_src, ETH_P_ARP)
        arp = struct.pack('!HHBBH6s4s6s4s',
                          ARP_HRD_ETHERNET, ARP_PROT_IPV4, 6, 4,
                          self.op, self.sha, self.spa, self.tha, self.tpa)
        return eth + arp

    @classmethod
    def parse(cls, data):
        eth_dst, eth_src, etype = struct.unpack('!6s6sH', data[:14])
        if etype != ETH_P_ARP:
            raise ValueError('not an ARP frame (etype=%#06x)' % etype)
        hrd, prot, hln, pln, op, sha, spa, tha, tpa = struct.unpack(
            '!HHBBH6s4s6s4s', data[14:42])
        f = cls(op, sha, spa, tha, tpa, eth_src=eth_src, eth_dst=eth_dst)
        f.raw = data[:42]
        return f

    def __repr__(self):
        return ('ARPFrame(op=%s sha=%s spa=%s tha=%s tpa=%s)'
                % (self.op, mac_to_str(self.sha), ip_to_str(self.spa),
                   mac_to_str(self.tha), ip_to_str(self.tpa)))


class ARPGuardDecider:
    """Spoof-detection state machine. Pure logic, no I/O."""

    def __init__(self, gateway_ip='192.0.2.1', gateway_mac='00:11:22:33:44:55',
                 block_threshold=2):
        self.gateway_ip = gateway_ip
        self.gateway_baseline = mac_to_bytes(gateway_mac)
        self.block_threshold = block_threshold
        self.arp_table = {}          # ip(bytes) -> mac(bytes)
        self.suspicious = defaultdict(int)
        self.events = []
        self.stats = {
            'total': 0, 'requests': 0, 'replies': 0,
            'suspicious': 0, 'mismatch': 0,
        }

    @staticmethod
    def _ipkey(ip):
        return ip_to_bytes(ip) if isinstance(ip, str) else ip

    def process(self, frame):
        """Feed a parsed ARPFrame; returns decision dict (or None)."""
        self.stats['total'] += 1
        if frame.op == ARP_OP_REQUEST:
            self.stats['requests'] += 1
        elif frame.op == ARP_OP_REPLY:
            self.stats['replies'] += 1

        spa = frame.spa
        sha = frame.sha

        # Ignore broadcast / zero MACs.
        if sha in (BROADCAST_MAC, ZERO_MAC):
            return None

        # Baseline the gateway once.
        if spa == self._ipkey(self.gateway_ip):
            if self.gateway_baseline is None:
                self.gateway_baseline = sha
                self._learn(spa, sha)
                return None
            if sha != self.gateway_baseline:
                self.stats['suspicious'] += 1
                self.stats['mismatch'] += 1
                self.suspicious[ip_to_str(spa)] += 1
                ev = {
                    'event': 'SPOOF', 'op': frame.op,
                    'ip': ip_to_str(spa),
                    'expected_mac': mac_to_str(self.gateway_baseline),
                    'observed_mac': mac_to_str(sha),
                    'count': self.suspicious[ip_to_str(spa)],
                    'blocked': self.suspicious[ip_to_str(spa)] >= self.block_threshold,
                }
                self.events.append(ev)
                return ev

        # Generic duplicate-IP check: same IP claimed by two MACs.
        key = spa
        if self._ipkey(self.gateway_ip) != key and key in self.arp_table:
            if self.arp_table[key] != sha:
                self.stats['suspicious'] += 1
                res = {
                    'event': 'DUPLICATE', 'op': frame.op,
                    'ip': ip_to_str(spa),
                    'expected_mac': mac_to_str(self.arp_table[key]),
                    'observed_mac': mac_to_str(sha),
                    'count': 1, 'blocked': False,
                }
                self.events.append(res)
                return res

        self._learn(spa, sha)
        return None

    def _learn(self, spa, sha):
        self.arp_table[spa] = sha

    def summary(self):
        return dict(self.stats)


class ARPGuardEngine:
    """Wraps a source of raw bytes and runs the decider."""

    def __init__(self, decider=None, **kwargs):
        self.decider = decider or ARPGuardDecider(**kwargs)
        self.running = True

    def feed_bytes(self, data):
        try:
            frame = ARPFrame.parse(data)
        except (ValueError, struct.error) as e:
            return {'event': 'PARSE_ERR', 'error': str(e)}
        return self.decider.process(frame)


class ARPSimulator:
    """Local simulator that generates genuinely-malformed ARP traffic."""

    @staticmethod
    def legitimate_gateway_reply(gw_mac='00:11:22:33:44:55',
                                 gw_ip='192.0.2.1'):
        return ARPFrame.reply(
            sha=gw_mac, spa=gw_ip,
            tha='00:00:00:00:00:00', tpa='192.0.2.50',
            eth_src=gw_mac, eth_dst=BROADCAST_MAC).build()

    @staticmethod
    def spoofed_gateway_reply(attacker_mac='00:11:22:33:44:66',
                              gw_ip='192.0.2.1'):
        return ARPFrame.reply(
            sha=attacker_mac, spa=gw_ip,
            tha='00:00:00:00:00:00', tpa='192.0.2.50',
            eth_src=attacker_mac, eth_dst=BROADCAST_MAC).build()

    @staticmethod
    def spoofed_gateway_request(attacker_mac='00:11:22:33:44:66',
                                gw_ip='192.0.2.1'):
        return ARPFrame.request(
            sha=attacker_mac, spa=gw_ip, tpa='192.0.2.50',
            eth_src=attacker_mac).build()


def run_pipe_harness(decider_kwargs):
    """
    Offline harness: build ARP bytes, feed them through the real parser and
    decider, and print a deterministic report. No sockets required.
    """
    decider = ARPGuardDecider(**decider_kwargs)
    engine = ARPGuardEngine(decider=decider)
    sim = ARPSimulator()

    test_frames = [
        ('legit_gateway_reply', sim.legitimate_gateway_reply()),
        ('spoof_gateway_reply', sim.spoofed_gateway_reply()),
        ('spoof_gateway_request', sim.spoofed_gateway_request()),
        ('spoof_again', sim.spoofed_gateway_reply()),
    ]

    print('=== N1 ARP Guard: offline decider harness ===')
    for name, data in test_frames:
        result = engine.feed_bytes(data)
        if result and result.get('event') == 'SPOOF':
            print(f'[{name}] SPOOF DETECTED ip={result["ip"]} '
                  f'expected={result["expected_mac"]} '
                  f'observed={result["observed_mac"]} '
                  f'count={result["count"]} blocked={result["blocked"]}')
        else:
            print(f'[{name}] ok (no flag)')

    stats = decider.summary()
    print('\n=== Stats ===')
    for k, v in stats.items():
        print(f'  {k}: {v}')

    flagged = [e for e in decider.events if e['event'] == 'SPOOF']
    if flagged and flagged[-1]['blocked']:
        print('\n[RESULT] PASS - spoof flagged and threshold-block reached')
        return 0
    print('\n[RESULT] FAIL - expected spoof detection')
    return 1


def run_live(interface, decider_kwargs, block=False, log_file=None, timeout=None):
    """Live sniffing via scapy (requires installed scapy + raw/root)."""
    if not _SCAPY:
        print('ERROR: live sniffing requires scapy (pip install scapy). '
              'Use the offline harness without --live.')
        return 1

    from scapy.all import Ether as sEther
    from scapy.all import ARP as sARP

    decider = ARPGuardDecider(**decider_kwargs)
    engine = ARPGuardEngine(decider=decider)
    start = time.time()

    def cb(pkt):
        if pkt.haslayer(sARP):
            raw = bytes(pkt)
            result = engine.feed_bytes(raw)
            _report(result)
        if timeout and time.time() - start > timeout:
            raise KeyboardInterrupt

    def _report(result):
        if not result:
            return
        if result['event'] == 'SPOOF':
            line = (f'[SPOOF] ip={result["ip"]} '
                    f'expected={result["expected_mac"]} '
                    f'observed={result["observed_mac"]} count={result["count"]}')
        elif result['event'] == 'DUPLICATE':
            line = (f'[DUPLICATE-IP] ip={result["ip"]} '
                    f'mac1={result["expected_mac"]} mac2={result["observed_mac"]}')
        else:
            return
        print(line)
        if block and result.get('blocked'):
            print(f'[BLOCK] would block ip={result["ip"]}')
        if log_file:
            with open(log_file, 'a') as f:
                f.write('%s,%s\n' % (datetime.now().isoformat(), line))

    print(f'=== Live ARP monitoring on {interface} === (Ctrl+C to stop)')
    sniff(iface=interface, filter='arp', prn=cb, store=0)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='N1 - ARP Guard: ARP spoofing detector (pure stdlib core).')
    parser.add_argument('--gateway-ip', default='192.0.2.1',
                        help='Gateway IP to protect (TEST-NET default)')
    parser.add_argument('--gateway-mac', default='00:11:22:33:44:55',
                        help='Expected gateway MAC (lab default)')
    parser.add_argument('--threshold', type=int, default=2,
                        help='Suspicion count before block decision')
    parser.add_argument('--harness', action='store_true',
                        help='Run offline decider harness (no privileges)')
    parser.add_argument('--live', action='store_true',
                        help='Enable live sniffing (needs root+scapy)')
    parser.add_argument('--iface', '-i', default='eth0',
                        help='Interface for live mode')
    parser.add_argument('--block', action='store_true',
                        help='When a spoof passes threshold, note block')
    parser.add_argument('--log', help='CSV/event log path')
    parser.add_argument('--timeout', type=int, help='Live mode duration (s)')

    args = parser.parse_args(argv)

    dkw = {'gateway_ip': args.gateway_ip,
           'gateway_mac': args.gateway_mac,
           'block_threshold': args.threshold}

    if args.harness or not args.live:
        return run_pipe_harness(dkw)

    if not _SCAPY:
        print('ERROR: live mode requires scapy. Run without --live (harness).')
        return 1
    if os.geteuid() != 0:
        print('ERROR: live mode requires root (raw sockets). '
              'Prefer the offline harness without --live.')
        return 1
    return run_live(args.iface, dkw, args.block, args.log, args.timeout)


if __name__ == '__main__':
    sys.exit(main())
