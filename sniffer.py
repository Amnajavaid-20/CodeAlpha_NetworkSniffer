#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer
Captures packets with Scapy and displays source/destination, protocol, and payload.

FOR EDUCATIONAL USE ONLY: capture traffic only on networks you own or are authorised to monitor.

Usage examples (run as Administrator/root):
    python sniffer.py                       # capture until Ctrl+C
    python sniffer.py -c 50                 # capture 50 packets
    python sniffer.py -f "tcp port 80"      # BPF filter
    python sniffer.py -i eth0 -o out.pcap   # pick interface, save pcap
    python sniffer.py --list-interfaces
"""
import argparse
import datetime
from collections import Counter

from scapy.all import (sniff, wrpcap, get_if_list, Ether, IP, IPv6, TCP, UDP,
                       ICMP, ARP, DNS, DNSQR, Raw)

stats = Counter()
captured = []


def payload_preview(packet, limit=64):
    """Return a printable preview of the packet payload."""
    if packet.haslayer(Raw):
        data = bytes(packet[Raw].load)[:limit]
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return ""


def tcp_flags(flags):
    names = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}
    return ",".join(names[f] for f in str(flags) if f in names) or "NONE"


def process_packet(packet):
    captured.append(packet)
    stats["total"] += 1
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"\n[{stats['total']}] {ts} " + "-" * 50)

    if packet.haslayer(Ether):
        print(f"  MAC : {packet[Ether].src} -> {packet[Ether].dst}")

    if packet.haslayer(ARP):
        stats["ARP"] += 1
        a = packet[ARP]
        op = "who-has" if a.op == 1 else "is-at"
        print(f"  ARP : {op} {a.pdst} (from {a.psrc})")
        return

    if packet.haslayer(IP):
        ip = packet[IP]
        src, dst, ttl = ip.src, ip.dst, ip.ttl
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        src, dst, ttl = ip.src, ip.dst, ip.hlim
    else:
        stats["other"] += 1
        print(f"  Other: {packet.summary()}")
        return

    print(f"  IP  : {src} -> {dst}  (TTL={ttl}, len={len(packet)})")

    if packet.haslayer(TCP):
        stats["TCP"] += 1
        t = packet[TCP]
        print(f"  TCP : port {t.sport} -> {t.dport}  flags=[{tcp_flags(t.flags)}] seq={t.seq}")
        if 80 in (t.sport, t.dport):
            print("  Note: HTTP is UNENCRYPTED - payload may be readable")
        elif 443 in (t.sport, t.dport):
            print("  Note: HTTPS - payload is encrypted")
    elif packet.haslayer(UDP):
        stats["UDP"] += 1
        u = packet[UDP]
        print(f"  UDP : port {u.sport} -> {u.dport}  len={u.len}")
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            stats["DNS"] += 1
            print(f"  DNS : query for {packet[DNSQR].qname.decode(errors='ignore')}")
    elif packet.haslayer(ICMP):
        stats["ICMP"] += 1
        print(f"  ICMP: type={packet[ICMP].type} code={packet[ICMP].code}")
    else:
        stats["other"] += 1
        print(f"  Proto number: {getattr(ip, 'proto', getattr(ip, 'nh', '?'))}")

    preview = payload_preview(packet)
    if preview:
        print(f"  Payload (first 64 bytes): {preview}")


def print_summary():
    print("\n" + "=" * 60)
    print("CAPTURE SUMMARY")
    print("=" * 60)
    for key in ("total", "TCP", "UDP", "ICMP", "DNS", "ARP", "other"):
        print(f"  {key:<6}: {stats[key]}")


def main():
    p = argparse.ArgumentParser(description="CodeAlpha Basic Network Sniffer")
    p.add_argument("-i", "--interface", help="interface to sniff on (default: Scapy default)")
    p.add_argument("-c", "--count", type=int, default=0, help="number of packets (0 = unlimited)")
    p.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 80"')
    p.add_argument("-o", "--output", help="save captured packets to a .pcap file")
    p.add_argument("--list-interfaces", action="store_true", help="list interfaces and exit")
    args = p.parse_args()

    if args.list_interfaces:
        print("\n".join(get_if_list()))
        return

    print("[*] Starting capture... press Ctrl+C to stop")
    try:
        sniff(iface=args.interface, filter=args.filter or None,
              prn=process_packet, count=args.count, store=False)
    except PermissionError:
        print("[!] Permission denied. Run as Administrator (Windows) or with sudo (Linux/macOS).")
        return
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[!] Error: {e}\n    On Windows, install Npcap (https://npcap.com) first.")
        return

    print_summary()
    if args.output and captured:
        wrpcap(args.output, captured)
        print(f"[*] Saved {len(captured)} packets to {args.output}")


if __name__ == "__main__":
    main()
