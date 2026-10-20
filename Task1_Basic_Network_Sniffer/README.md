# CodeAlpha Project: Basic Network Sniffer

## Overview
A beginner-friendly Python packet sniffer built with Scapy. It captures packets from a selected network interface and displays:
- Timestamp and packet size
- Protocol (ARP, DNS, TCP, UDP, ICMP, IP/IPv6, or other)
- Source and destination IP addresses
- Source and destination ports when available
- TCP flags, ICMP type/code, and ARP request/reply
- Optional short printable payload preview

## Ethical and legal use
Run this tool only on your own device/network or where you have explicit permission. Do not use it to intercept other people's private traffic. Payload previews are disabled by default because packets can contain sensitive information.

## Requirements
- Python 3.9 or newer
- Scapy
- Windows: Npcap installed, and run the terminal as Administrator for live capture
- Linux/macOS: packet-capture permissions may be required (for example, root or suitable capabilities)

## Installation

### Windows (PowerShell)
1. Install Python from the official Python website and enable **Add Python to PATH**.
2. Install Npcap from its official website. The default installation options are generally suitable.
3. Open PowerShell in this project folder.
4. Create and activate a virtual environment (recommended):

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

5. Install the dependency:

   ```powershell
   python -m pip install -r requirements.txt
   ```

6. Open PowerShell **as Administrator** for live capture.

### Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
sudo python sniffer.py --count 25
```

## Usage

List available interfaces:
```bash
python sniffer.py --list-interfaces
```

Capture 25 packets using the default interface:
```bash
python sniffer.py --count 25
```

Capture packets on a named interface:
```bash
python sniffer.py --interface "Wi-Fi" --count 50
```

Capture only TCP packets:
```bash
python sniffer.py --count 50 --filter "tcp"
```

Capture DNS traffic:
```bash
python sniffer.py --count 30 --filter "udp port 53"
```

Capture ICMP packets (for example, while you ping a host you control):
```bash
python sniffer.py --count 20 --filter "icmp"
```

Show a short payload preview:
```bash
python sniffer.py --count 20 --payload-preview
```

Capture until Ctrl+C:
```bash
python sniffer.py --count 0
```

> Interface names vary by computer. Use `--list-interfaces` to see what Scapy detects. BPF filters may depend on the installed packet-capture backend.

## Understanding the output
Example (illustrative only; addresses and packet details will differ):
```text
[12:30:01.123] TCP      60 bytes  192.168.1.10 -> 142.250.72.14 (51522 -> 443) flags=S
[12:30:01.130] DNS      78 bytes  192.168.1.10 -> 192.168.1.1 (53000 -> 53)
[12:30:02.010] ICMP     98 bytes  192.168.1.10 -> 192.168.1.1 type=8 code=0
```

- **Source IP:** sender's IP address.
- **Destination IP:** receiver's IP address.
- **Ports:** identify the application/service endpoints for TCP/UDP.
- **Protocol:** identifies how the packet is being carried or what it is used for.
- **Length:** packet size in bytes as captured.
- **TCP flags:** `S` means SYN (connection setup), `A` means ACK, and `F` means FIN (connection close).
- **DNS:** domain-name lookup traffic. DNS can also use TCP; this simple label recognizes DNS when Scapy decodes it.
- **Payload preview:** a short, printable view of a limited number of bytes; encrypted HTTPS application content will not normally appear as readable text.

## How network packet capture works
1. Applications generate data.
2. Transport protocols such as TCP or UDP package data with ports.
3. IP adds source and destination addresses for routing.
4. The network interface sends or receives frames.
5. The packet-capture library exposes captured packets to this program.
6. The program decodes known protocol layers and prints a summary.

## Limitations
- The program reports packets visible to the selected interface; it does not automatically see all traffic on the local network.
- Modern HTTPS/TLS traffic is encrypted. A packet capture generally reveals metadata such as IPs, ports, sizes, and timing, not the encrypted application contents.
- Protocol classification is intentionally basic and prioritizes ARP, DNS, TCP, UDP, ICMP, then IP/IPv6.
- This is an educational project, not a full network-analysis or intrusion-detection system.

## Suggested test
1. Start the sniffer with `python sniffer.py --count 25`.
2. In another terminal, visit a website you are allowed to access or run `ping 1.1.1.1`.
3. Observe the source/destination addresses, protocols, ports, lengths, and TCP flags.
4. Repeat with `--filter "icmp"` while running a ping command.
5. Record your observations for the project report.

## Project structure
```text
CodeAlpha_BasicNetworkSniffer/
├── sniffer.py
├── requirements.txt
└── README.md
```
