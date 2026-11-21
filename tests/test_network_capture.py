"""
Unit tests for CyberShield-Relay Network Capture Engine (TShark / Wireshark).
Validates:
1. TShark binary detection and version availability.
2. Network interface enumeration.
3. Live capture start, status query, and graceful stop.
4. PCAP output file generation.
"""

import unittest
import os
import time
from network.packet_capture import PacketCaptureEngine


class TestNetworkCapture(unittest.TestCase):
    def setUp(self):
        self.engine = PacketCaptureEngine()

    def test_tshark_detection(self):
        """Verifies TShark binary is detected or fallback status is accurately reported."""
        status = self.engine.get_status()
        self.assertIn("is_capturing", status)
        self.assertIn("is_available", status)
        # On this machine, TShark is installed at C:\Program Files\Wireshark\tshark.exe
        if self.engine.is_available():
            self.assertTrue(os.path.exists(self.engine.tshark_path))

    def test_interface_enumeration(self):
        """Verifies network capture interfaces can be listed."""
        if not self.engine.is_available():
            self.skipTest("TShark not available on this environment.")

        ifaces = self.engine.list_interfaces()
        self.assertIsInstance(ifaces, list)
        self.assertGreater(len(ifaces), 0)
        first = ifaces[0]
        self.assertIn("id", first)
        self.assertIn("name", first)
        self.assertIn("is_loopback", first)

    def test_capture_lifecycle(self):
        """Verifies starting, monitoring, and stopping a live capture session."""
        if not self.engine.is_available():
            self.skipTest("TShark not available on this environment.")

        loop = [i for i in self.engine.list_interfaces() if i.get("is_loopback")]
        if not loop:
            self.skipTest("No loopback capture adapter (install Npcap with loopback support).")
        start_res = self.engine.start_capture(interface=loop[0]["id"], capture_filter="tcp port 5000 or tcp port 5443")
        self.assertTrue(start_res.get("success"), f"Failed to start: {start_res}")

        status = self.engine.get_status()
        self.assertTrue(status.get("is_capturing"))

        time.sleep(1.5)

        stop_res = self.engine.stop_capture()
        self.assertTrue(stop_res.get("success"), f"Failed to stop: {stop_res}")

        status_after = self.engine.get_status()
        self.assertFalse(status_after.get("is_capturing"))

        # Verify output PCAP file was created
        output_file = stop_res.get("output_file")
        self.assertTrue(output_file and os.path.exists(output_file))


if __name__ == "__main__":
    unittest.main()
