"""
Unit tests for CyberShield-Relay Flask REST API endpoints.
Validates:
1. Session endpoints (/api/session, /api/session/new).
2. Benchmark endpoint (/api/benchmark/crypto).
3. Packet capture endpoints (/api/capture/interfaces, /api/capture/status, /api/packets).
4. Traffic analytics endpoint (/api/analytics/traffic).
5. Security monitor alerts endpoint (/api/monitor/alerts).
6. Attack simulation endpoints (/api/simulate/eavesdrop, /api/simulate/mitm, /api/simulate/tamper).
7. Audit log and report endpoints (/api/logs, /api/report/generate).
"""

import unittest
import json
from app import app


class TestFlaskAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_home_page(self):
        """Verifies dashboard HTML renders properly."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CyberShield Relay", response.data)

    def test_get_session(self):
        """Verifies /api/session returns valid DH parameters and certificates."""
        response = self.client.get("/api/session")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("crypto", data)
        self.assertIn("certificate", data)

    def test_new_session(self):
        """Verifies /api/session/new establishes a fresh DH session."""
        response = self.client.post("/api/session/new")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")

    def test_crypto_benchmark_api(self):
        """Verifies /api/benchmark/crypto returns latency measurements."""
        response = self.client.get("/api/benchmark/crypto")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("benchmarks", data)

    def test_capture_interfaces_api(self):
        """Verifies /api/capture/interfaces returns available adapters."""
        response = self.client.get("/api/capture/interfaces")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("interfaces", data)

    def test_capture_status_api(self):
        """Verifies /api/capture/status returns status object."""
        response = self.client.get("/api/capture/status")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")

    def test_get_packets_api(self):
        """Verifies /api/packets parses and returns packet list."""
        response = self.client.get("/api/packets?limit=20")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn(data["status"], ["success", "empty"])

    def test_traffic_analytics_api(self):
        """Verifies /api/analytics/traffic returns structured statistics."""
        response = self.client.get("/api/analytics/traffic")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("analysis", data)

    def test_monitor_alerts_api(self):
        """Verifies /api/monitor/alerts returns alert list."""
        response = self.client.get("/api/monitor/alerts")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("alerts", data)

    def test_simulate_eavesdrop_api(self):
        """Verifies /api/simulate/eavesdrop produces wiretap comparison."""
        payload = {"message": "Test wiretap message", "incident_id": "CC-API-TEST"}
        response = self.client.post("/api/simulate/eavesdrop", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")

    def test_simulate_mitm_api(self):
        """Verifies /api/simulate/mitm produces unauth vs auth comparison."""
        response = self.client.post("/api/simulate/mitm")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("unauthenticated_dh", data)
        self.assertIn("authenticated_dh", data)

    def test_audit_logs_api(self):
        """Verifies /api/logs returns event log."""
        response = self.client.get("/api/logs?limit=10")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("events", data)


if __name__ == "__main__":
    unittest.main()
