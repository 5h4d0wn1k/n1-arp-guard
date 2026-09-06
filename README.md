# N1 — ARP Guard

Real-time ARP spoofing detection and blocking tool.

## Overview

This project implements an ARP spoofing detection system with a **pure standard-library
packet engine** — it builds and parses real Ethernet + ARP frames by hand (no scapy
dependency required). The core detection state machine runs fully unprivileged and
deterministically, so it can be tested offline.

## What Works

- **Real ARP packet construction/parsing** (`ARPFrame.build` / `ARPFrame.parse`) — builds
  genuine 14-byte Ethernet + 28-byte ARP frames, round-trips through the parser.
- **Spoof-decider state machine** (`ARPGuardDecider`) — flags a gateway address claimed by
  a MAC other than the expected baseline; also detects any IP claimed by two MACs.
- **Offline harness** (`--harness`) — feeds genuinely-built ARP frames (legit, spoofed
  reply, spoofed request) through the real parser + decider with no privileges.
- **Live sniffing** (`--live/--iface`) — real interface monitoring, gated behind an
  explicit flag; requires root + scapy (optional).

## Installation

No external dependencies for the core. Optional for live sniffing:

```bash
pip install scapy
```

## Usage

```bash
# Offline decider harness (no privileges, deterministic)
python3 arp_guard.py --harness

# Custom gateway / threshold
python3 arp_guard.py --harness --gateway-ip 192.0.2.1 --gateway-mac 00:11:22:33:44:55 --threshold 2

# Live monitoring on a real interface (root + scapy)
sudo python3 arp_guard.py --live --iface eth0 --gateway-ip 192.0.2.1
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

> Authorized own-lab use only. Use documented placeholders (192.0.2.x, 00:11:22:33:44:55).

1. **Prepare a controlled lab**: two VM/container hosts, one acting as the "attacker".
2. Have the attacker send ARP replies claiming `192.0.2.1` with a different MAC.
3. Run `sudo python3 arp_guard.py --live --iface <lab-iface> --gateway-ip 192.0.2.1 --gateway-mac 00:11:22:33:44:55`.
4. Confirm the spoofed replies are flagged with the expected vs observed MAC.
5. Set `--threshold 2` and drive multiple spoofs; confirm the `[BLOCK]` decision line appears.
6. Verify restore: when the attacker stops spoofing, the correct gateway MAC returns.

## Metrics

Core offline harness is deterministic and unit-tested:

- ARP frame round-trip parse: PASS (7 unit tests)
- Legit gateway reply: no false positive
- Spoofed gateway reply: flagged (count increments, threshold-block reached)
- Duplicate-IP two-MAC conflict: detected
- Exit code: `0` on successful harness, `1` on failure

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

## License

MIT
