# CodeAlpha_BasicNetworkSniffer

**Task 1: CodeAlpha Cyber Security Internship**
Author:Amna Javaid

A command-line network packet sniffer written in Python using Scapy. It captures live traffic, breaks each packet into its protocol layers, and displays the information needed to understand how data moves across a network.

## Features
- Live packet capture with optional BPF filters (e.g. `-f "tcp port 80"`)
- Parses Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP and DNS
- Displays source/destination MAC and IP addresses, ports, TCP flags, TTL and packet length
- Shows a printable preview of the payload (first 64 bytes)
- Flags unencrypted HTTP (port 80) versus encrypted HTTPS (port 443)
- Summary statistics by protocol at the end of each capture
- Optional export to a `.pcap` file that can be opened in Wireshark

## Requirements
- Python 3.8 or newer
- Scapy (`pip install -r requirements.txt`)
- **Windows:** [Npcap](https://npcap.com) installed (with WinPcap API-compatible mode) and the terminal run as Administrator
- **Linux/macOS:** run with `sudo`

## Installation
```bash
git clone https://github.com/<your-username>/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer
pip install -r requirements.txt
```

## Usage
```bash
python sniffer.py --list-interfaces         # show available network interfaces
python sniffer.py -c 20                     # capture 20 packets
python sniffer.py -f "icmp" -c 10           # capture only ICMP (ping) traffic
python sniffer.py -f "udp port 53" -c 10    # capture only DNS traffic
python sniffer.py -i "Wi-Fi" -c 30          # choose an interface
python sniffer.py -c 30 -o capture.pcap     # save packets to a pcap file
```

| Option | Description |
|---|---|
| `-i`, `--interface` | Interface to sniff on (default: Scapy's default) |
| `-c`, `--count` | Number of packets to capture (0 = until Ctrl+C) |
| `-f`, `--filter` | BPF filter expression |
| `-o`, `--output` | Save captured packets to a `.pcap` file |
| `--list-interfaces` | List interfaces and exit |

## Sample output
```
[6] 22:19:14 --------------------------------------------------
  MAC : e4:70:b8:92:25:4d -> 94:0b:19:36:24:21
  IP  : 192.168.100.46 -> 192.168.100.1  (TTL=128, len=92)
  UDP : port 52830 -> 53  len=58
  DNS : query for mobile.events.data.microsoft.com.
```

## Screenshots
**Start of capture**

![Sniffer output](screenshots/sniffer_top.png)

**End of capture with summary**

![Capture summary](screenshots/sniffer_summary.png)

## Test results
A 20-packet capture on my home Wi-Fi network produced:

| Protocol | Packets |
|---|---|
| TCP | 16 |
| UDP | 4 |
| DNS | 2 |
| ICMP / ARP / other | 0 |

Observations:
- Most traffic was HTTPS on port 443, so payloads appear as unreadable bytes because they are encrypted with TLS.
- A TCP handshake was visible (SYN, SYN-ACK, then ACK) between my machine and a remote server.
- A DNS lookup showed my computer asking the router (192.168.100.1) to resolve a Microsoft domain name.
- Some UDP traffic on port 443 is QUIC (HTTP/3), which is also encrypted.

## How it works
1. `sniff()` puts the network card into capture mode and passes each packet to `process_packet()`.
2. Scapy dissects the packet into layers (Ethernet > IP > TCP/UDP > Raw).
3. The program reads header fields from each layer and prints them. The Raw layer is the application payload.
4. Counts