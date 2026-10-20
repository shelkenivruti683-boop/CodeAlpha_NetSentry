
from network_sniffer.statistics import print_statistics

sample_records = [
    {
        "protocol": "TCP",
        "source_ip": "2001:db8::1",
        "destination_port": 443,
        "packet_length_bytes": 170,
    },
    {
        "protocol": "TCP",
        "source_ip": "2001:db8::1",
        "destination_port": 443,
        "packet_length_bytes": 113,
    },
    {
        "protocol": "UDP",
        "source_ip": "2001:db8::2",
        "destination_port": 53,
        "packet_length_bytes": 28,
    },
]

print_statistics(sample_records)
