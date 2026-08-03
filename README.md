<h1 align="center">vamp-icmp-shadow</h1>
<p align="center">
  <strong>Covert ICMP data channel for Red/Blue Team detection validation and IDS/IPS rule testing</strong><br>
  <em>VampSecure Labs · Security Research Division</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/license-research%20only-red?style=flat-square">
  <img src="https://img.shields.io/badge/VampSecure-Labs-8B0000?style=flat-square">
</p>

---

## Overview

`vamp-icmp-shadow` implements a covert data channel over ICMP for use in authorized Red/Blue Team lab environments. It demonstrates that the payload field of ICMP Echo Request packets can be used as a data exfiltration vector, bypassing network controls that filter only by protocol or port number without performing deep packet inspection on ICMP content.

The tool's primary purpose is **defensive**: validating that IDS/IPS rules (Snort, Suricata) correctly detect non-standard ICMP payloads, training Blue Team analysts to recognize the traffic pattern, and documenting the attack vector in network security audit reports. It must not be used outside of self-owned lab environments or without explicit written authorization.

Data is obfuscated via XOR with a shared key, encoded in Base64, prefixed with a magic marker (`VSHDW:`), and split into fixed-size chunks transmitted as individual ICMP Echo Request packets. The receiver side reassembles and decodes the stream.

## Features

- **`send` mode** — XOR-encrypts a message with the configured key, Base64-encodes it, fragments it into 200-byte chunks, and sends each chunk as an ICMP Echo Request (type=8) with sequential sequence numbers
- **`listen` mode** — captures ICMP Echo Request packets via Scapy BPF filter `icmp`, verifies the `VSHDW:` magic prefix, decodes Base64, applies XOR to recover plaintext, and displays captured messages in Rich panels with source IP and sequence number
- **XOR + Base64 obfuscation** — symmetric cipher (XOR key repeats cyclically); the same key decrypts: `XOR(XOR(data, key), key) = data`
- **Configurable key** via `--key` parameter or `--key-file` (first line of file) — default key is `VAMP_KEY_2026`
- **Magic-prefix filtering** — the receiver silently ignores all ICMP traffic that does not carry the `VSHDW:` prefix, making it quiet in mixed-traffic environments
- **Verbose mode** (`-v`) shows all ICMP packets received including those without the magic prefix, useful for debugging IDS rule placement
- **Chunk-based fragmentation** — messages longer than 200 obfuscated bytes are automatically split; the receiver accumulates chunks per source IP ordered by ICMP sequence number
- **Root privilege enforcement** — exits with an error if not run as root, as raw packet capture requires `CAP_NET_RAW`
- Rich console output: sender displays a per-packet table with payload preview, byte count, and status; receiver shows a panel per decoded message

## Requirements

```
pip install -r requirements.txt
```

| Package | Version |
|---------|---------|
| `scapy` | >= 2.5.0 |
| `rich`  | >= 13.7.0 |

Standard library: `argparse`, `base64`, `os`, `sys`, `time`, `datetime`, `pathlib`.

## Installation

```bash
git clone https://github.com/belky-me/vamp-icmp-shadow.git
cd vamp-icmp-shadow
pip install -r requirements.txt
```

Requires root or `CAP_NET_RAW` capability for both send and listen modes.

## Usage

```bash
python vamp_icmp_shadow.py --help
```

Two subcommands are available: `send` and `listen`.

```
usage: vamp-icmp-shadow {send,listen} ...

subcommands:
  send      Send a message via the ICMP Shadow channel
  listen    Listen for incoming ICMP Shadow channel traffic
```

### Examples

**Send a short message to a lab target (default key):**
```bash
sudo python vamp_icmp_shadow.py send -t 192.168.1.10 -d "shadow test"
```

**Send a message with a custom XOR key:**
```bash
sudo python vamp_icmp_shadow.py send -t 192.168.1.10 -d "exfil payload" -k "MY_SECRET_KEY"
```

**Send using a key loaded from a file:**
```bash
sudo python vamp_icmp_shadow.py send -t 192.168.1.10 -d "test" --key-file /etc/lab/icmp.key
```

**Send with verbose output (shows per-packet errors and status):**
```bash
sudo python vamp_icmp_shadow.py send -t 10.0.0.5 -d "blue team test" -v
```

**Listen on interface eth0 for incoming Shadow channel traffic:**
```bash
sudo python vamp_icmp_shadow.py listen -i eth0
```

**Listen with a custom key and verbose mode (shows non-Shadow ICMP too):**
```bash
sudo python vamp_icmp_shadow.py listen -i eth0 -k "MY_SECRET_KEY" -v
```

**Listen using a key file:**
```bash
sudo python vamp_icmp_shadow.py listen -i eth0 --key-file /etc/lab/icmp.key
```

## Protocol Overview

```
Sender:
  plaintext → XOR(key) → Base64 → "VSHDW:" + B64_CHUNK
  Each chunk → ICMP Echo Request (type=8, seq=N, payload=VSHDW:...)

Receiver:
  ICMP Echo Request captured → check for "VSHDW:" prefix
  → Base64 decode → XOR(key) → plaintext
  → display with source IP and sequence number
```

Chunk size: 200 bytes of the obfuscated Base64 string per packet.  
Inter-packet delay: 50 ms to avoid overwhelming the network stack.

## Blue Team Detection Notes

This tool is designed to make its own traffic detectable. Example Suricata signature that fires on the `VSHDW:` magic prefix in ICMP payloads:

```
alert icmp any any -> any any (msg:"VampSecure ICMP Shadow channel"; \
  content:"VSHDW:"; itype:8; sid:9000001; rev:1;)
```

Use this tool to verify that your IDS signature correctly triggers before writing it into the production ruleset.

## Part of VampSecure Labs Toolkit

This tool is part of the **VampSecure Labs Security Toolkit** — a collection of research-grade security tools for authorized penetration testing and red/blue team exercises.

- Full toolkit: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For authorized security testing only.
