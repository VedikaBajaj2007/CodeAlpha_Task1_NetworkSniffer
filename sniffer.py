#!/usr/bin/env python3

# Network Packet Sniffer using Scapy

import sys
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
except ImportError:
    print("Scapy not installed. Run: pip install scapy")
    sys.exit(1)

# Protocol mapping
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}


def get_payload(packet):
    if packet.haslayer(Raw):
        try:
            return packet[Raw].load.decode("utf-8", errors="replace")
        except:
            return "Unreadable payload"
    return "No payload"


def process_packet(packet):
    # Only process IP packets
    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    src_ip = ip.src
    dst_ip = ip.dst
    proto_num = ip.proto
    protocol = PROTO_MAP.get(proto_num, "OTHER")

    payload = get_payload(packet)

    time = datetime.now().strftime("%H:%M:%S")

    print("=" * 50)
    print(f"Time       : {time}")
    print(f"Source IP  : {src_ip}")
    print(f"Dest IP    : {dst_ip}")
    print(f"Protocol   : {protocol}")

    # Ports
    if packet.haslayer(TCP):
        print(f"Ports      : {packet[TCP].sport} -> {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print(f"Ports      : {packet[UDP].sport} -> {packet[UDP].dport}")

    print(f"Payload    : {payload[:100]}")
    print("=" * 50)


def main():
    print("Starting Packet Sniffer... Press Ctrl+C to stop")

    try:
        sniff(prn=process_packet, store=False)

    except KeyboardInterrupt:
        print("\nStopped safely.")
        sys.exit(0)

    except PermissionError:
        print("Run as Administrator / root")
        sys.exit(1)


if __name__ == "__main__":
    main()