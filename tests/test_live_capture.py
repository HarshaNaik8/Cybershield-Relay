"""
Live wire test: captures real loopback traffic with TShark/Npcap while the real servers run, then proves
what an observer sees for a plaintext request versus the application's encrypted incident packet.
Skipped (never faked) when TShark, a loopback capture adapter or capture permission is unavailable.
"""

import os
import ssl
import threading
import time
import unittest

import requests
from werkzeug.serving import make_server

import app as cyber_app
from network.packet_capture import PacketCaptureEngine
from network.packet_parser import PacketParser
from network_engine import HOST, HTTP_PORT, HTTPS_PORT, SERVER_CERT_PATH, SERVER_KEY_PATH, ensure_certificates

MARKER = "SECRET-MARKER-ZX81"


def payload_bytes(pkt):
    """Rebuilds the raw TCP payload bytes of a parsed packet from its hex dump."""
    out = bytearray()
    for line in str(pkt.get("hex_dump", "")).splitlines():
        out += bytes.fromhex(line.split("  ", 1)[1].replace(" ", ""))
    return bytes(out)


def stream_text(packets, needle):
    """Text of every TCP stream (both directions) whose payload contains `needle` (e.g. the receiver URL)."""
    streams = {}
    for p in packets:
        streams.setdefault(p["stream_id"], []).append(p)
    return [wire_text(v) for v in streams.values() if needle in wire_text(v)]


def wire_text(packets):
    """What an observer can read: all captured TCP payload bytes, decoded as latin-1 text."""
    return b"".join(payload_bytes(p) for p in packets).decode("latin-1")


class TestLiveWireCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = PacketCaptureEngine()
        if not cls.engine.is_available():
            raise unittest.SkipTest("TShark is not installed.")
        loop = [i for i in cls.engine.list_interfaces() if i.get("is_loopback")]
        if not loop:
            raise unittest.SkipTest("No loopback capture adapter (Npcap loopback support) found.")
        cls.iface = loop[0]["id"]
        ensure_certificates()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(SERVER_CERT_PATH, SERVER_KEY_PATH)
        cls.servers = [make_server(HOST, HTTPS_PORT, cyber_app.app, ssl_context=ctx, threaded=True),
                       make_server(HOST, HTTP_PORT, cyber_app.app, threaded=True)]
        for s in cls.servers:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        for s in getattr(cls, "servers", []):
            s.shutdown()

    def capture(self, action):
        res = self.engine.start_capture(interface=self.iface, capture_filter="tcp port 5000 or tcp port 5443")
        if not res.get("success"):
            self.skipTest(f"Capture could not start (permissions?): {res.get('message')}")
        time.sleep(2.0)
        action()
        time.sleep(1.5)
        stop = self.engine.stop_capture()
        self.assertTrue(stop.get("success"), stop)
        return PacketParser.parse_pcap(stop["output_file"], max_packets=500)

    def test_plaintext_is_visible_and_encrypted_is_not(self):
        def send_plain():  # a deliberately unprotected request, used only as the comparison baseline
            requests.post(f"http://{HOST}:{HTTP_PORT}/api/officer_b/receive", timeout=10,
                          json={"incident_id": "PLAIN", "message": MARKER})

        plain = self.capture(send_plain)
        self.assertGreater(len(plain), 0)
        self.assertTrue(all(p["dst_ip"] == "127.0.0.1" or p["src_ip"] == "127.0.0.1" for p in plain))
        self.assertIn(MARKER, wire_text(plain), "plaintext report must be readable on the wire")

        def send_encrypted():
            requests.post(f"http://{HOST}:{HTTP_PORT}/api/transmit", timeout=10,
                          json={"incident_id": "ENC", "message": MARKER, "protocol": "HTTP"})

        enc = self.capture(send_encrypted)
        # The browser -> Officer A request (/api/transmit) is the local UI hop where the user types the report.
        # The Officer A -> Officer B leg is the stream that hits /api/officer_b/receive: that is the network under test.
        legs = stream_text(enc, "POST /api/officer_b/receive")
        self.assertGreater(len(legs), 0, "no Officer A -> Officer B stream captured")
        for leg in legs:
            self.assertNotIn(MARKER, leg, "incident text (request or response) must not appear on the A->B wire")
            self.assertIn("ciphertext", leg)   # JSON field names and headers are visible over plain HTTP

    def test_https_hides_http_metadata(self):
        def send_https():
            requests.post(f"http://{HOST}:{HTTP_PORT}/api/transmit", timeout=10,
                          json={"incident_id": "TLSCHK", "message": MARKER, "protocol": "HTTPS"})

        pkts = self.capture(send_https)
        tls_side = [p for p in pkts if 5443 in (p["src_port"], p["dst_port"])]
        self.assertGreater(len(tls_side), 0)
        text = wire_text(tls_side)
        for marker in (MARKER, "/api/officer_b/receive", "ciphertext", "X-Client"):
            self.assertNotIn(marker, text)
        self.assertTrue(any("TLS" in p["protocol"] for p in tls_side))


if __name__ == "__main__":
    unittest.main()
