# Project Report: Basic Network Sniffer

**Organization:** CodeAlpha  
**Domain:** Cyber Security  
**Project:** Basic Network Sniffer  
**Language:** Python  
**Library:** Scapy

## 1. Objective
To build a Python program that captures network packets and displays useful packet information, including source and destination addresses, protocols, packet size, transport ports, and a limited optional payload preview.

## 2. Tools and Technologies
- Python 3
- Scapy packet-capture and packet-decoding library
- Npcap on Windows (or an appropriate packet-capture backend on another operating system)
- Command-line interface

## 3. Methodology
1. Install Python and Scapy.
2. Select a network interface.
3. Capture a limited number of packets or stop a continuous capture manually.
4. Decode common protocol layers.
5. Print a concise summary for each packet.
6. Use optional BPF filters to focus on TCP, DNS, or ICMP traffic.
7. Interpret the results to understand packet flow.

## 4. Information Displayed
- Timestamp
- Protocol classification
- Packet length
- Source and destination IP addresses (when present)
- Source and destination ports (for TCP/UDP)
- TCP flags, ICMP type/code, and ARP operation
- Optional limited printable payload preview

## 5. Protocol Concepts
- **ARP:** Helps map local IPv4 addresses to link-layer addresses.
- **IP/IPv6:** Carries addressing information used to route packets.
- **TCP:** Connection-oriented transport protocol; common flags include SYN, ACK, and FIN.
- **UDP:** Connectionless transport protocol used by services such as DNS.
- **ICMP:** Used for network diagnostics and error reporting.
- **DNS:** Resolves domain names to network records.

## 6. Security and Privacy
The tool should only be used on devices and networks owned by the operator or where explicit permission has been granted. Payload preview is disabled by default and limited in length. Captured data should not be published if it contains private information.

## 7. Testing Plan
Complete the following tests on an authorized device and record actual results:
- Run a default capture and confirm that packet summaries appear.
- Capture TCP traffic with the `tcp` filter.
- Capture DNS traffic with the `udp port 53` filter, where visible.
- Capture ICMP traffic while pinging a host you control.
- Confirm that the source/destination fields and packet lengths are shown.

### Results table (fill in after running)
| Test | Command | Expected observation | Actual result |
|---|---|---|---|
| Default capture | `python sniffer.py --count 25` | Up to 25 packet summaries | Fill in |
| TCP filter | `python sniffer.py --count 20 --filter "tcp"` | TCP packets only | Fill in |
| DNS filter | `python sniffer.py --count 20 --filter "udp port 53"` | Visible UDP DNS packets | Fill in |
| ICMP filter | `python sniffer.py --count 20 --filter "icmp"` | ICMP packets, if generated/visible | Fill in |

## 8. Limitations
- Only traffic visible to the chosen interface can be captured.
- HTTPS/TLS payloads are encrypted and are not generally readable in a basic packet capture.
- The program uses simple protocol classification and is not a full forensic analyzer.
- Live capture may require administrator/root privileges and a compatible packet-capture backend.

## 9. Conclusion
This project demonstrates the basics of packet capture and protocol analysis with Python and Scapy. It provides a command-line view of network traffic metadata and supports simple filters for learning how network communication works.

**Important:** Run the program and replace the testing placeholders with genuine observations before submitting the report. Do not claim tests passed unless you have actually run them.
