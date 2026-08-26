# N1 — ARP Guard

Real-time ARP spoofing detection and blocking tool.

## Overview

This project implements an ARP spoofing detection system that:
- Monitors ARP requests/replies for spoofing
- Detects duplicate IPs with different MACs
- Alerts on ARP cache poisoning attempts
- Auto-blocks attackers via iptables
- Logs all suspicious activity to CSV

## Features

- **Real-time monitoring**: Sniff ARP packets on network interface
- **Spoof detection**: Identify ARP cache poisoning attempts
- **Auto-blocking**: Block attackers via iptables (optional)
- **CSV logging**: Record all suspicious activity
- **Statistics**: Track packet counts and attack metrics

## Installation

```bash
pip install scapy
```

## Usage

```bash
# Basic monitoring
sudo python3 arp_guard.py --interface eth0

# With auto-blocking
sudo python3 arp_guard.py --interface eth0 --block

# With logging
sudo python3 arp_guard.py --interface eth0 --log arp_log.csv
```

## Example Output

```
=== N1 — ARP Guard ===
Interface: eth0
Auto-block: False
Log file: arp_log.csv

[SPOOF DETECTED] 192.168.1.100
  Original MAC: aa:bb:cc:dd:ee:ff
  New MAC:      11:22:33:44:55:66
  Type:         REPLY
  Count:        1

=== Statistics ===
Total packets: 1234
ARP requests:  890
ARP replies:   344
Suspicious:    5
Blocked:       0
Known hosts:   23
```

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
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
