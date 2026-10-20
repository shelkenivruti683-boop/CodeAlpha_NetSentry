
from datetime import datetime, timezone
from scapy.all import IP, IPv6, TCP, UDP, ICMP



def analyze_packet(packet):
    """Extract metadata from IPv4 or IPv6 packets."""

    if packet.haslayer(IP):
        ip_layer = packet[IP]
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
    else:
        return None

    protocol = "Other IP"
    source_port = ""
    destination_port = ""

    if packet.haslayer(TCP):
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    elif (
        packet.haslayer(IPv6)
        and packet[IPv6].nh == 58
    ):
        protocol = "ICMPv6"

    timestamp = datetime.fromtimestamp(
        float(packet.time),
        tz=timezone.utc
    ).isoformat(timespec="seconds")

    return {
        "timestamp_utc": timestamp,
        "source_ip": ip_layer.src,
        "destination_ip": ip_layer.dst,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_length_bytes": len(packet),
    }