
import unittest

from scapy.all import IP, TCP, UDP, ICMP
from network_sniffer.analyzer import analyze_packet


class TestPacketAnalyzer(unittest.TestCase):

    def test_tcp_packet(self):
        packet = (
            IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=12345, dport=443)
        )
        result = analyze_packet(packet)

        self.assertEqual(result["protocol"], "TCP")
        self.assertEqual(result["source_port"], 12345)
        self.assertEqual(result["destination_port"], 443)

    def test_udp_packet(self):
        packet = (
            IP(src="192.0.2.11", dst="198.51.100.21")
            / UDP(sport=53000, dport=53)
        )
        result = analyze_packet(packet)

        self.assertEqual(result["protocol"], "UDP")
        self.assertEqual(result["destination_port"], 53)

    def test_icmp_packet(self):
        packet = (
            IP(src="192.0.2.12", dst="198.51.100.22")
            / ICMP()
        )
        result = analyze_packet(packet)

        self.assertEqual(result["protocol"], "ICMP")

    def test_non_ip_packet(self):
        result = analyze_packet(TCP())
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
