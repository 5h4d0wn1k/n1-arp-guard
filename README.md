> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# N1 — ARP Guard

ARP spoofing guard — a pure-standard-library ARP sniffing detector that builds
and parses real Ethernet + ARP frames, binds MAC/IP baselines, monitors for
anomalies, and alerts on suspicious ARP traffic.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/n1-arp-guard)](#)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/n1-arp-guard)](#)

## Why this project

ARP spoofing is one of the oldest and most reliable local-network attack
techniques: an attacker broadcasts forged ARP replies to hijack traffic meant
for the gateway. Defending a network starts with detecting that drift — a MAC
address that changes, or two devices claiming the same IP. This guard is built
around a real packet engine (`ARPFrame.build`/`parse`) with no scapy dependency,
so the core detection state machine runs unprivileged and deterministically in
CI-style offline harnesses. Live sniffing on a real interface is supported via
scapy when installed, but the default is always the safe, offline path. Use it
to monitor networks you own or are explicitly authorized to defend.

## Features

- **Real ARP frame construction/parsing** — byte-exact Ethernet + ARP
  (RFC 826) build and round-trip through the parser
- **Spoof-decider state machine** — flags a gateway claimed by a MAC other than
  the expected baseline; also detects any IP claimed by two different MACs
- **Threshold-based block decision** — configurable suspicion count
  (`--threshold`) before a `[BLOCK]` decision is emitted
- **Offline harness** (default) — feeds legit, spoofed-reply, and spoofed-request
  frames through the real parser and decider, no privileges required
- **Live sniffing** — `--live`/`--iface` mode via scapy (requires root)
- **Event logging** — optional CSV log of detected events

## Quickstart

Prerequisites: Python 3.6+ (stdlib-only core). Live mode requires root and
`pip install scapy`.

```bash
# Offline decider harness (no privileges, deterministic) — also the default
python3 firmware/arp_guard.py --harness

# Custom gateway / threshold
python3 firmware/arp_guard.py --harness --gateway-ip 192.0.2.1 \
  --gateway-mac 00:11:22:33:44:55 --threshold 2

# Live monitoring on a real interface (root + scapy)
sudo python3 firmware/arp_guard.py --live --iface eth0 \
  --gateway-ip 192.0.2.1 --gateway-mac 00:11:22:33:44:55

# Unit tests
python3 -m unittest discover -s tests
```

## Live lab test plan

> Authorized own-lab use only (TEST-NET placeholders).

1. Set up two hosts; one acts as the "attacker".
2. Attacker sends ARP replies claiming `192.0.2.1` with a different MAC.
3. Run live mode and confirm the spoofed replies are flagged with expected vs
   observed MAC.
4. Set `--threshold 2` and drive multiple spoofs; confirm the `[BLOCK]`
   decision line appears.
5. Stop the attacker; confirm the correct gateway MAC returns to normal.

## Project structure

- `firmware/arp_guard.py` — packet engine, decider, simulator, harness, live mode
- `tests/test_arp_guard.py` — deterministic offline unit tests

## Documentation

- [ETHICS.md](ETHICS.md) — intended use and user responsibility
- [SCOPE.md](SCOPE.md) — authorized-testing checklist
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities in this repo
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute safely

## Contributing

Contributions for legitimate lab, education, and defensive use are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE). Educational and authorized-use only; provided
**AS IS**, without warranty.