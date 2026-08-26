#!/usr/bin/env python3
"""
N1 — ARP Guard
Real-time ARP spoofing detection and blocking

Features:
- Monitor ARP requests/replies for spoofing
- Detect duplicate IPs with different MACs
- Alert on ARP cache poisoning attempts
- Auto-block attackers via iptables
- Log all suspicious activity

Usage:
    sudo python3 arp_guard.py [--interface eth0] [--block] [--log arp_log.csv]

WARNING: Educational use only. Test on your own network.
"""

import argparse
import csv
import os
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime
from scapy.all import ARP, Ether, sniff, send, conf
import threading

class ARPGuard:
    def __init__(self, interface, auto_block=False, log_file=None):
        self.interface = interface
        self.auto_block = auto_block
        self.log_file = log_file
        self.arp_table = {}  # IP -> MAC mapping
        self.suspicious = defaultdict(int)  # IP -> suspicious count
        self.blocked = set()
        self.running = True
        self.lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'arp_requests': 0,
            'arp_replies': 0,
            'suspicious': 0,
            'blocked': 0
        }
        
        print(f"\n=== N1 — ARP Guard ===")
        print(f"Interface: {interface}")
        print(f"Auto-block: {auto_block}")
        print(f"Log file: {log_file or 'None'}")
        print("=" * 30)
    
    def start(self):
        """Start ARP monitoring"""
        print("\nStarting ARP monitoring...")
        print("Press Ctrl+C to stop\n")
        
        # Start sniffer
        sniff(
            iface=self.interface,
            filter="arp",
            prn=self.process_packet,
            store=0,
            stop_filter=lambda x: not self.running
        )
    
    def process_packet(self, pkt):
        """Process ARP packet"""
        self.stats['total_packets'] += 1
        
        if not pkt.haslayer(ARP):
            return
        
        arp = pkt[ARP]
        
        # ARP Request
        if arp.op == 1:
            self.stats['arp_requests'] += 1
            self.check_arp(arp.psrc, arp.hwsrc, "REQUEST")
        
        # ARP Reply
        elif arp.op == 2:
            self.stats['arp_replies'] += 1
            self.check_arp(arp.psrc, arp.hwsrc, "REPLY")
    
    def check_arp(self, ip, mac, pkt_type):
        """Check for ARP spoofing"""
        with self.lock:
            # Skip broadcast/multicast
            if mac in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"]:
                return
            
            # First time seeing this IP
            if ip not in self.arp_table:
                self.arp_table[ip] = mac
                self.log_event("NEW", ip, mac, pkt_type)
                return
            
            # IP already has a different MAC
            if self.arp_table[ip] != mac:
                self.suspicious[ip] += 1
                self.stats['suspicious'] += 1
                
                old_mac = self.arp_table[ip]
                print(f"\n[SPOOF DETECTED] {ip}")
                print(f"  Original MAC: {old_mac}")
                print(f"  New MAC:      {mac}")
                print(f"  Type:         {pkt_type}")
                print(f"  Count:        {self.suspicious[ip]}")
                
                # Log to CSV
                self.log_event("SPOOF", ip, mac, pkt_type, old_mac)
                
                # Auto-block if enabled
                if self.auto_block and self.suspicious[ip] >= 3:
                    self.block_attacker(mac, ip)
                
                # Update ARP table
                self.arp_table[ip] = mac
    
    def block_attacker(self, mac, ip):
        """Block attacker via iptables"""
        if mac in self.blocked:
            return
        
        print(f"\n[BLOCKING] {mac} ({ip})")
        
        try:
            # Block by MAC
            os.system(f"iptables -A INPUT -m mac --mac-source {mac} -j DROP")
            # Block by IP
            os.system(f"iptables -A INPUT -s {ip} -j DROP")
            
            self.blocked.add(mac)
            self.stats['blocked'] += 1
            
            print(f"  Blocked {mac} and {ip}")
            self.log_event("BLOCKED", ip, mac, "AUTO")
            
        except Exception as e:
            print(f"  Error blocking: {e}")
    
    def log_event(self, event_type, ip, mac, pkt_type, old_mac=None):
        """Log event to CSV"""
        if not self.log_file:
            return
        
        try:
            with open(self.log_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(),
                    event_type,
                    ip,
                    mac,
                    pkt_type,
                    old_mac,
                    self.suspicious.get(ip, 0)
                ])
        except Exception as e:
            print(f"  Log error: {e}")
    
    def show_stats(self):
        """Show statistics"""
        print(f"\n=== Statistics ===")
        print(f"Total packets: {self.stats['total_packets']}")
        print(f"ARP requests:  {self.stats['arp_requests']}")
        print(f"ARP replies:   {self.stats['arp_replies']}")
        print(f"Suspicious:    {self.stats['suspicious']}")
        print(f"Blocked:       {self.stats['blocked']}")
        print(f"Known hosts:   {len(self.arp_table)}")
        print("=" * 20)
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        self.show_stats()
        print("\nARP Guard stopped.")

def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    guard.stop()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='N1 — ARP Guard: ARP spoofing detector')
    parser.add_argument('--interface', '-i', default='eth0', help='Network interface')
    parser.add_argument('--block', '-b', action='store_true', help='Auto-block attackers')
    parser.add_argument('--log', '-l', help='Log file (CSV)')
    
    args = parser.parse_args()
    
    # Check root
    if os.geteuid() != 0:
        print("ERROR: ARP Guard requires root privileges")
        print("Run with: sudo python3 arp_guard.py")
        sys.exit(1)
    
    # Check interface
    try:
        from scapy.all import get_if_list
        if args.interface not in get_if_list():
            print(f"ERROR: Interface {args.interface} not found")
            print(f"Available: {get_if_list()}")
            sys.exit(1)
    except:
        pass
    
    # Create guard
    global guard
    guard = ARPGuard(args.interface, args.block, args.log)
    
    # Handle signals
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start
    guard.start()

if __name__ == '__main__':
    main()
