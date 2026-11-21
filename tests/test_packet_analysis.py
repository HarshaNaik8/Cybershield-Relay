"""
Unit tests for CyberShield-Relay Packet Parser & Traffic Analyzer.
Validates:
1. Deep packet inspection across Layers 2-7.
2. Wireshark-style 16-byte hex and ASCII dump formatting.
3. Summary traffic statistics (total bytes, avg packet size, protocol distribution).
4. TCP stream grouping and handshake duration tracking.
"""

import unittest
import os
from network.packet_parser import PacketParser
from network.network_analyzer import NetworkAnalyzer
from network import CAPTURES_DIR
from network.packet_capture import PacketCaptureEngine

TSHARK_AVAILABLE = PacketCaptureEngine().tshark_path is not None


class TestPacketAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample_pcap = os.path.join(CAPTURES_DIR, "cybershield_traffic.pcap")

    def test_pcap_parsing_field_extraction(self):
        """Verifies parsing PCAP file extracts standard header fields."""
        if not os.path.exists(self.sample_pcap):
            self.skipTest("Sample PCAP not present.")
        if not TSHARK_AVAILABLE:
            self.skipTest("TShark not installed.")

        packets = PacketParser.parse_pcap(self.sample_pcap, max_packets=50)
        self.assertIsInstance(packets, list)
        self.assertGreater(len(packets), 0)

        pkt = packets[0]
        self.assertIn("packet_number", pkt)
        self.assertIn("protocol", pkt)
        for key in ("src_ip", "dst_ip", "src_port", "dst_port", "tcp_flags", "timestamp", "stream_id"):
            self.assertIn(key, pkt)
        self.assertIn("length", pkt)
        self.assertEqual(pkt["tcp_flags"], "SYN")      # first packet of a TCP stream; no character-encoding artefacts

    def test_hex_dump_format(self):
        """Verifies hex & ASCII dump format follows standard 16-byte layout."""
        sample_bytes = b"GET /api/session HTTP/1.1\r\nHost: 127.0.0.1:5000\r\n\r\n"
        dump = PacketParser.format_hex_ascii_dump(sample_bytes)

        self.assertIn("0000", dump["hex_dump"])
        self.assertIn("47 45 54", dump["hex_dump"])
        self.assertIn("|GET /api/session|", dump["combined_dump"])

    def test_network_traffic_analyzer(self):
        """Verifies traffic statistics, distributions, and stream aggregation."""
        if not os.path.exists(self.sample_pcap):
            self.skipTest("Sample PCAP not present.")
        if not TSHARK_AVAILABLE:
            self.skipTest("TShark not installed.")

        packets = PacketParser.parse_pcap(self.sample_pcap, max_packets=100)
        analysis = NetworkAnalyzer.analyze_packets(packets)

        self.assertEqual(analysis["total_packets"], len(packets))
        self.assertGreater(analysis["total_bytes"], 0)
        self.assertIn("protocol_distribution", analysis)
        self.assertIn("size_buckets", analysis)
        self.assertGreater(len(analysis["tcp_streams"]), 0)


class TestStreamDirection(unittest.TestCase):
    def test_server_is_the_service_port_endpoint_even_if_capture_starts_mid_stream(self):
        pk = [{"packet_number": 1, "stream_id": 0, "src_ip": "127.0.0.1", "src_port": 5000, "dst_ip": "127.0.0.1",
               "dst_port": 51000, "length": 60, "protocol": "TCP"},
              {"packet_number": 2, "stream_id": 0, "src_ip": "127.0.0.1", "src_port": 51000, "dst_ip": "127.0.0.1",
               "dst_port": 5000, "length": 60, "protocol": "TCP"}]
        st = NetworkAnalyzer.analyze_packets(pk)["tcp_streams"][0]
        self.assertEqual(st["server_endpoint"], "127.0.0.1:5000")
        self.assertEqual((st["client_to_server"], st["server_to_client"]), (1, 1))


class TestTrafficMonitor(unittest.TestCase):
    """Deterministic rule-based alerts (no machine learning is claimed or implemented)."""

    @staticmethod
    def pkt(num, src, dst, proto="TCP", flags="ACK", preview=""):
        return {"packet_number": num, "src_port": src, "dst_port": dst, "protocol": proto,
                "tcp_flags": flags, "payload_preview": preview, "timestamp": "t"}

    def rules(self, packets):
        from network.traffic_monitor import TrafficMonitor
        return {a["rule"] for a in TrafficMonitor.evaluate_packets(packets)}

    def test_normal_reply_traffic_is_not_flagged(self):
        self.assertEqual(self.rules([self.pkt(1, 53000, 5000), self.pkt(2, 5000, 53000), self.pkt(3, 5443, 53001)]), set())

    def test_unexpected_port_flagged(self):
        self.assertIn("RULE_UNEXPECTED_PORT", self.rules([self.pkt(1, 40000, 6666)]))

    def test_syn_fin_flagged(self):
        self.assertIn("RULE_SUSPICIOUS_TCP_FLAGS", self.rules([self.pkt(1, 40000, 5000, flags="SYN, FIN")]))

    def test_plaintext_incident_over_http_flagged(self):
        self.assertIn("RULE_PLAINTEXT_SENSITIVE_LEAK", self.rules([self.pkt(1, 40000, 5000, "HTTP", "ACK, PSH", "incident CC-1")]))


if __name__ == "__main__":
    unittest.main()
