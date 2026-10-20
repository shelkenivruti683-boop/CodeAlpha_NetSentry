
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
from datetime import datetime

INTERFACE = "Wi-Fi"
PACKET_LIMIT = 10
packet_count = 0
started_at = time.monotonic()


def analyze_packet(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1

    ip = packet[IP]
    protocol = "OTHER"
    source_port = "-"
    destination_port = "-"

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    print("-" * 55)
    print(f"Packet       : {packet_count}/{PACKET_LIMIT}")
    print(f"Time         : {datetime.now().isoformat(timespec='seconds')}")
    print(f"Protocol     : {protocol}")
    print(f"Source IP    : {ip.src}")
    print(f"Destination IP: {ip.dst}")
    print(f"Source Port  : {source_port}")
    print(f"Destination Port: {destination_port}")
    print(f"Packet Length: {len(packet)} bytes")


if __name__ == "__main__":
    print("NETSENTRY - LIVE METADATA CAPTURE")
    print(f"Interface: {INTERFACE}")
    print(f"Maximum packets: {PACKET_LIMIT}")
    print("Waiting for IP traffic...")

    try:
        sniff(
            iface=INTERFACE,
            filter="ip",
            prn=analyze_packet,
            count=PACKET_LIMIT,
            store=False
        )
        print("\nCapture completed.")

    except PermissionError:
        print("Permission denied. Check Windows/Npcap permissions.")

    except Exception as error:
        print(f"Capture error: {error}")


import csv
from pathlib import Path
from datetime import datetime



INTERFACE = "Wi-Fi"
PACKET_LIMIT = 10

REPORT_DIR = Path("reports")
REPORT_FILE = REPORT_DIR / "live_traffic_report.csv"

records = []


def analyze_packet(packet):
    if IP not in packet:
        return

    ip = packet[IP]
    protocol = "OTHER"
    source_port = ""
    destination_port = ""

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"

    record = {
        "Timestamp": datetime.now().isoformat(timespec="seconds"),
        "Protocol": protocol,
        "Source IP": ip.src,
        "Destination IP": ip.dst,
        "Source Port": source_port,
        "Destination Port": destination_port,
        "Packet Length": len(packet),
    }

    records.append(record)

    print(
        f"{len(records)}/{PACKET_LIMIT} | {protocol} | "
        f"{ip.src} -> {ip.dst} | {len(packet)} bytes"
    )


if __name__ == "__main__":
    print("NETSENTRY - LIVE METADATA CAPTURE")
    print(f"Interface: {INTERFACE}")
    print(f"Maximum packets: {PACKET_LIMIT}")

    try:
        sniff(
            iface=INTERFACE,
            filter="ip",
            prn=analyze_packet,
            count=PACKET_LIMIT,
            store=False
        )

        REPORT_DIR.mkdir(parents=True, exist_ok=True)

        fields = [
            "Timestamp", "Protocol", "Source IP",
            "Destination IP", "Source Port",
            "Destination Port", "Packet Length"
        ]

        with REPORT_FILE.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(records)

        print(f"\nPackets recorded: {len(records)}")
        print(f"CSV report saved to: {REPORT_FILE}")

    except PermissionError:
        print("Permission denied. Check Npcap/Windows permissions.")
    except Exception as error:
        print(f"Capture error: {error}")
