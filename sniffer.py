#!/usr/bin/env python3
"""
CodeAlpha Project: Basic Network Sniffer
Captures and summarizes packets on a network interface using Scapy.

Use only on networks/devices you own or have explicit permission to monitor.
Payload preview is intentionally limited to avoid unnecessarily displaying sensitive data.
"""
import argparse
import datetime as dt
import sys

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, conf
except ImportError:
    print("Scapy is not installed. Run: python -m pip install -r requirements.txt")
    raise SystemExit(1)


def get_protocol(packet):
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(IPv6):
        return "IPv6"
    if packet.haslayer(IP):
        return "IP"
    return "OTHER"


def get_endpoints(packet):
    """Return source, destination, and optional ports."""
    if packet.haslayer(ARP):
        arp = packet[ARP]
        return arp.psrc or "-", arp.pdst or "-", None, None

    if packet.haslayer(IP):
        src, dst = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        src, dst = packet[IPv6].src, packet[IPv6].dst
    else:
        src, dst = "-", "-"

    sport = dport = None
    if packet.haslayer(TCP):
        sport, dport = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        sport, dport = packet[UDP].sport, packet[UDP].dport
    return src, dst, sport, dport


def payload_preview(packet, limit=32):
    """Return a short, printable preview; do not print entire payloads."""
    if not packet.haslayer(Raw):
        return ""
    data = bytes(packet[Raw].load)[:limit]
    # Replace non-printable bytes to keep terminal output readable.
    preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
    suffix = "..." if len(bytes(packet[Raw].load)) > limit else ""
    return f' payload="{preview}{suffix}"'


def summarize(packet, show_payload=False):
    timestamp = dt.datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3]
    protocol = get_protocol(packet)
    src, dst, sport, dport = get_endpoints(packet)
    length = len(packet)

    endpoint_text = f"{src} -> {dst}"
    if sport is not None and dport is not None:
        endpoint_text += f" ({sport} -> {dport})"

    details = ""
    if packet.haslayer(TCP):
        flags = str(packet[TCP].flags)
        details = f" flags={flags}"
    elif packet.haslayer(ICMP):
        details = f" type={packet[ICMP].type} code={packet[ICMP].code}"
    elif packet.haslayer(ARP):
        details = f" operation={'request' if packet[ARP].op == 1 else 'reply'}"

    line = f"[{timestamp}] {protocol:<5} {length:>5} bytes  {endpoint_text}{details}"
    if show_payload:
        line += payload_preview(packet)
    print(line)


def main():
    parser = argparse.ArgumentParser(
        description="Capture and summarize packets for learning on an authorized network."
    )
    parser.add_argument("-i", "--interface", help="Network interface name (default: Scapy default)")
    parser.add_argument("-c", "--count", type=int, default=25,
                        help="Number of packets to capture (default: 25; use 0 for unlimited)")
    parser.add_argument("-f", "--filter", default="",
                        help='Optional BPF filter, e.g. "tcp", "udp port 53", or "icmp"')
    parser.add_argument("--payload-preview", action="store_true",
                        help="Show a short printable preview of packet payload bytes")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List interfaces detected by Scapy and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        print("Interfaces detected by Scapy:")
        try:
            for iface in conf.ifaces.values():
                print(f"  {iface.name}  ({iface.description or 'no description'})")
        except Exception:
            print(conf.ifaces)
        return

    if args.count < 0:
        parser.error("--count must be 0 or a positive integer")

    print("CodeAlpha — Basic Network Sniffer")
    print("Capture is limited to networks/devices you own or are authorized to monitor.")
    print(f"Interface: {args.interface or 'Scapy default'}")
    print(f"Packet count: {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print(f"BPF filter: {args.filter or '(none)'}")
    print("-" * 100)

    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            prn=lambda pkt: summarize(pkt, args.payload_preview),
            store=False,
            count=args.count
        )
    except PermissionError:
        print("\nPermission denied. On Windows, open PowerShell as Administrator and ensure Npcap is installed.")
        raise SystemExit(2)
    except OSError as exc:
        print(f"\nCapture error: {exc}")
        print("Check that Npcap/libpcap is installed, the interface name is correct, and the filter is valid.")
        raise SystemExit(2)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as exc:
        print(f"\nUnexpected error: {exc}")
        raise SystemExit(2)

    print("-" * 100)
    print("Capture finished.")


if __name__ == "__main__":
    main()
