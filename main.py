
import argparse
import sys
from collections import Counter
from network_sniffer.statistics import print_statistics

from network_sniffer.analyzer import analyze_packet
from network_sniffer.capture import (
    demo_packets,
    live_capture,
    list_interfaces,
)
from network_sniffer.exporter import export_csv


MAX_PACKETS = 10


def print_protocol_summary(records):
    print("\nNETSENTRY - PROTOCOL SUMMARY")
    print("-" * 35)

    if not records:
        print("No packets available for summary.")
        return

    counts = Counter(record["protocol"] for record in records)

    print(f"Total packets: {len(records)}")

    for protocol, count in sorted(counts.items()):
        print(f"{protocol:<10}: {count}")

    total_bytes = sum(
        record["packet_length_bytes"] for record in records
    )
    print(f"Total packet bytes: {total_bytes}")
    print("-" * 35)


def run_analyzer(mode, interface=None, count=MAX_PACKETS):
    records = []

    output_path = (
        "reports/demo_traffic_report.csv"
        if mode == "demo"
        else "reports/live_traffic_report.csv"
    )

    def process_packet(packet):
        record = analyze_packet(packet)

        if record is not None:
            records.append(record)
            print(
                f'{record["protocol"]:<7} '
                f'{record["source_ip"]}:{record["source_port"]} -> '
                f'{record["destination_ip"]}:'
                f'{record["destination_port"]} '
                f'({record["packet_length_bytes"]} bytes)'
            )

    try:
        print("\nNETSENTRY - NETWORK TRAFFIC ANALYZER")

        if mode == "demo":
            print("Demo mode: synthetic packets only.")
            for packet in demo_packets():
                process_packet(packet)
        else:
            print("Live mode: authorized traffic only.")
            print("Metadata only; payloads are not displayed.")
            print(f"Interface: {interface}")
            print(f"Maximum packets: {count}")

            live_capture(
                count=count,
                callback=process_packet,
                interface=interface,
            )
        print_protocol_summary(records)

        print_statistics(records)

        report_path = export_csv(records, output_path)
        print(f"\nAnalyzed packets: {len(records)}")
        print(f"CSV report saved to: {report_path}")

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        if records:
            report_path = export_csv(records, output_path)
            print(f"Partial report saved to: {report_path}")

    except Exception as error:
        print(f"\nError: {error}")
        print("Check interface name, Npcap and permissions.")


def interactive_menu():
    while True:
        print("\n" + "=" * 42)
        print("       NETSENTRY - MAIN MENU")
        print("=" * 42)
        print("1. Demo Mode")
        print("2. Live Mode")
        print("3. List Network Interfaces")
        print("4. Exit")
        print("=" * 42)

        choice = input("Enter your choice (1-4): ").strip()

        if choice == "1":
            run_analyzer("demo")

        elif choice == "2":
            try:
                interfaces = list_interfaces()
                print("\nAvailable interfaces:")
                for item in interfaces:
                    print(f"  {item}")

                interface = input(
                    "\nEnter the exact Wi-Fi interface name or path: "
                ).strip()

                if not interface:
                    print("Interface name cannot be empty.")
                    continue

                count_text = input(
                    "Maximum packets (1-10, default 10): "
                ).strip()

                count = int(count_text) if count_text else MAX_PACKETS

                if not 1 <= count <= MAX_PACKETS:
                    print("Please enter a number from 1 to 10.")
                    continue

                confirm = input(
                    "Capture metadata on an authorized network? (y/n): "
                ).strip().lower()

                if confirm == "y":
                    run_analyzer(
                        "live",
                        interface=interface,
                        count=count,
                    )
                else:
                    print("Live capture cancelled.")

            except ValueError:
                print("Invalid number. Please enter 1 to 10.")
            except Exception as error:
                print(f"Interface error: {error}")

        elif choice == "3":
            try:
                interfaces = list_interfaces()
                print("\nAvailable network interfaces:")
                for item in interfaces:
                    print(f"  {item}")
                if not interfaces:
                    print("No interfaces found.")
            except Exception as error:
                print(f"Could not list interfaces: {error}")

        elif choice == "4":
            print("NETSENTRY closed. Goodbye!")
            break

        else:
            print("Invalid choice. Please select 1, 2, 3 or 4.")


def main():
    parser = argparse.ArgumentParser(
        description="NETSENTRY Network Traffic Analyzer"
    )
    parser.add_argument(
        "--menu",
        action="store_true",
        help="Open the interactive menu",
    )
    parser.add_argument(
        "--mode",
        choices=["demo", "live"],
        help="Run a mode directly instead of the menu",
    )
    parser.add_argument("--count", type=int, default=MAX_PACKETS)
    parser.add_argument("--interface", default=None)
    parser.add_argument("--list-interfaces", action="store_true")

    args = parser.parse_args()

    if args.list_interfaces:
        for interface in list_interfaces():
            print(interface)
        return 0

    if args.mode is None or args.menu:
        interactive_menu()
        return 0

    if not 1 <= args.count <= MAX_PACKETS:
        parser.error("--count must be between 1 and 10")

    if args.mode == "live" and not args.interface:
        parser.error(
            "Live mode requires --interface. "
            "Use --list-interfaces to find it."
        )

    run_analyzer(
        args.mode,
        interface=args.interface,
        count=args.count,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nNETSENTRY closed.")
