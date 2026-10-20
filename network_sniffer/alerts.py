
from collections import Counter


def detect_traffic_alerts(records):
    """Generate simple alerts from packet metadata."""

    alerts = []

    if not records:
        return ["No traffic data available to analyze."]

    # Rule 1: High packet count from one source IP
    source_counts = Counter(
        record["source_ip"]
        for record in records
        if record.get("source_ip")
    )

    for source_ip, count in source_counts.items():
        if count >= 10:
            alerts.append(
                f"High traffic: {source_ip} generated "
                f"{count} packets in this report."
            )

    # Rule 2: Unusually large packet
    for record in records:
        try:
            packet_size = int(record["packet_length_bytes"])
        except (KeyError, TypeError, ValueError):
            continue

        if packet_size > 1500:
            alerts.append(
                f"Large packet detected: {packet_size} bytes."
            )

    if not alerts:
        alerts.append("No alerts triggered.")

    return alerts
