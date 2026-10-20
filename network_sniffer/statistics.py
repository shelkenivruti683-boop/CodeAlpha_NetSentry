
from collections import Counter


def calculate_statistics(records):
    """Calculate summary statistics from packet metadata."""

    total_packets = len(records)

    if total_packets == 0:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "average_packet_size": 0,
            "protocol_counts": {},
            "top_source_ips": {},
            "top_destination_ports": {},
        }

    total_bytes = sum(
        int(record["packet_length_bytes"])
        for record in records
    )

    protocol_counts = Counter(
        record["protocol"] for record in records
    )

    source_ip_counts = Counter(
        record["source_ip"] for record in records
    )

    destination_port_counts = Counter(
        str(record["destination_port"])
        for record in records
        if record["destination_port"] != ""
    )

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "average_packet_size": round(
            total_bytes / total_packets, 2
        ),
        "protocol_counts": dict(protocol_counts),
        "top_source_ips": dict(source_ip_counts.most_common(5)),
        "top_destination_ports": dict(
            destination_port_counts.most_common(5)
        ),
    }


def print_statistics(records):
    """Print a readable traffic statistics report."""

    stats = calculate_statistics(records)

    print("\nNETSENTRY - TRAFFIC STATISTICS")
    print("-" * 38)
    print(f"Total packets       : {stats['total_packets']}")
    print(f"Total bytes         : {stats['total_bytes']}")
    print(f"Average packet size : {stats['average_packet_size']} bytes")

    print("\nProtocol counts:")
    if stats["protocol_counts"]:
        for protocol, count in sorted(
            stats["protocol_counts"].items()
        ):
            print(f"  {protocol:<12}: {count}")
    else:
        print("  No packets available.")

    print("\nTop source IPs:")
    for ip, count in stats["top_source_ips"].items():
        print(f"  {ip}: {count}")

    print("\nDestination ports:")
    for port, count in stats["top_destination_ports"].items():
        print(f"  Port {port}: {count}")

    print("-" * 38)
