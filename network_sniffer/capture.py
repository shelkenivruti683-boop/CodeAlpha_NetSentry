
from scapy.all import IP, TCP, UDP, ICMP, sniff, get_if_list
import time


def demo_packets():
    """Create synthetic packets for safe demonstration."""
    return [
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=51515, dport=443),

        IP(src="192.0.2.11", dst="198.51.100.21")
        / UDP(sport=53000, dport=53),

        IP(src="192.0.2.12", dst="198.51.100.22")
        / ICMP(),
    ]


def list_interfaces():
    """Return interfaces available to Scapy."""
    return get_if_list()


def live_capture(count, callback, interface=None, stop_event=None):
    """Capture a bounded number of packets with a timeout."""

    if not 1 <= count <= 10:
        raise ValueError("count must be between 1 and 10")

    interfaces = list_interfaces()

    if not interfaces:
        raise RuntimeError(
            "No network interfaces found. Check Npcap installation."
        )

    if not interface:
        raise ValueError("Please select a network interface.")

    matched_interface = next(
        (
            item for item in interfaces
            if item.strip().lower() == interface.strip().lower()
        ),
        None,
    )

    if matched_interface is None:
        raise ValueError(
            f"Unknown interface: {interface}. "
            "Use list_interfaces() to see available interfaces."
        )

    packet_count = 0
    started_at = time.monotonic()

    def packet_callback(packet):
        nonlocal packet_count

        if packet_count < count:
            packet_count += 1
            callback(packet)

    print(f"Using interface: {matched_interface}")
    print(f"Maximum packets: {count}")
    print("Capture duration: maximum 30 seconds")
    print("Waiting for network packets...")

    while (
        packet_count < count
        and time.monotonic() - started_at < 30
    ):
        if stop_event is not None and stop_event.is_set():
            break

        elapsed = time.monotonic() - started_at
        remaining_seconds = 30 - elapsed

        sniff(
            iface=matched_interface,
            prn=packet_callback,
            store=False,
            count=count - packet_count,
            timeout=min(1, remaining_seconds),
            stop_filter=lambda packet: (
                stop_event is not None and stop_event.is_set()
            ),
        )

    print(f"Raw packets received: {packet_count}")
    print("Packet capture finished.")


if __name__ == "__main__":
    print("Available Scapy interfaces:")
    for item in list_interfaces():
        print(item)
