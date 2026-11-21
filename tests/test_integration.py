"""
Integration tests: real HTTP (5000) and HTTPS (5443) servers, real sockets, real TLS certificate validation,
frontend/backend API contract, attack-demonstration endpoints and graceful error handling.
"""

import os
import ssl
import threading
import unittest

import requests
from werkzeug.serving import make_server

import app as cyber_app
from network_engine import (HOST, HTTP_PORT, HTTPS_PORT, SERVER_CERT_PATH, SERVER_KEY_PATH,
                            UNTRUSTED_CERT_PATH, RECEIVER_STATE, ensure_certificates)

BASE = f"http://{HOST}:{HTTP_PORT}"


class TestLiveSystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_certificates()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(SERVER_CERT_PATH, SERVER_KEY_PATH)
        cls.servers = [make_server(HOST, HTTPS_PORT, cyber_app.app, ssl_context=ctx, threaded=True),
                       make_server(HOST, HTTP_PORT, cyber_app.app, threaded=True)]
        for s in cls.servers:
            threading.Thread(target=s.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.shutdown()

    def send(self, protocol, incident="CC-1024", message="Zero-day found in edge gateway."):
        return requests.post(f"{BASE}/api/transmit", timeout=10,
                             json={"incident_id": incident, "message": message, "protocol": protocol}).json()

    # --- frontend/backend contract ------------------------------------------------------------
    def test_dashboard_and_static_assets_load(self):
        page = requests.get(BASE + "/", timeout=10)
        self.assertEqual(page.status_code, 200)
        self.assertIn("CyberShield", page.text)
        for asset in ("/static/script.js", "/static/style.css"):
            self.assertEqual(requests.get(BASE + asset, timeout=10).status_code, 200)

    # --- transport -----------------------------------------------------------------------------
    def test_http_round_trip(self):
        d = self.send("HTTP")
        rr = d["network_result"]["receiver_response"]
        self.assertEqual((rr["status"], rr["integrity"]), ("verified", "VALID"))
        self.assertFalse(d["network_result"]["cert_verified"])

    def test_https_round_trip_with_certificate_verification(self):
        d = self.send("HTTPS", message="Ransomware neutralised on subnet 10.0.4.0/24.")
        nr = d["network_result"]
        self.assertTrue(nr["cert_verified"])
        self.assertEqual(nr["receiver_response"]["decrypted_message"], "[CC-1024] Ransomware neutralised on subnet 10.0.4.0/24.")

    def test_negotiated_tls_version_is_1_3(self):
        ctx = ssl.create_default_context(cafile=SERVER_CERT_PATH)
        import socket
        with socket.create_connection((HOST, HTTPS_PORT)) as raw:
            with ctx.wrap_socket(raw, server_hostname=HOST) as tls:
                self.assertEqual(tls.version(), "TLSv1.3")

    def test_untrusted_certificate_is_rejected_by_client(self):
        with self.assertRaises(requests.exceptions.SSLError):
            requests.post(f"https://{HOST}:{HTTPS_PORT}/api/officer_b/receive", json={}, verify=UNTRUSTED_CERT_PATH, timeout=10)

    # --- receiver pipeline ---------------------------------------------------------------------
    def test_forged_tag_is_rejected_with_400(self):
        pkt = self.send("HTTP")["packet"]
        pkt = dict(pkt, nonce="fresh_" + os.urandom(4).hex(), hmac="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
        r = requests.post(f"{BASE}/api/officer_b/receive", json=pkt, timeout=10)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["code"], "HMAC_VERIFICATION_FAILED")

    def test_replayed_packet_is_rejected(self):
        pkt = self.send("HTTP")["packet"]
        r = requests.post(f"{BASE}/api/officer_b/receive", json=pkt, timeout=10)
        self.assertEqual(r.json()["code"], "REPLAY_DETECTED")

    def test_receiver_response_does_not_echo_plaintext(self):
        s = cyber_app.CURRENT_SESSION
        import datetime
        from crypto_engine import b64_encode
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        nonce = "msg_" + os.urandom(6).hex()
        iv, ct, tag = s.encrypt_incident("[CC-7] PLAINTEXT-SHOULD-STAY-AT-B", "CC-7", ts, nonce)
        pkt = {"incident_id": "CC-7", "timestamp": ts, "nonce": nonce, "iv": b64_encode(iv),
               "ciphertext": b64_encode(ct), "hmac": b64_encode(tag), "protocol": "HTTP"}
        r = requests.post(f"{BASE}/api/officer_b/receive", json=pkt, timeout=10)
        self.assertEqual(r.json()["status"], "verified")
        self.assertNotIn("PLAINTEXT-SHOULD-STAY-AT-B", r.text)
        self.assertNotIn("decrypted_message", r.json())

    def test_malformed_requests_are_handled(self):
        self.assertEqual(requests.post(f"{BASE}/api/transmit", json={"incident_id": "", "message": "x"}, timeout=10).status_code, 400)
        self.assertEqual(requests.post(f"{BASE}/api/transmit", json={"incident_id": "A", "message": ""}, timeout=10).status_code, 400)
        r = requests.post(f"{BASE}/api/officer_b/receive", json={}, timeout=10)
        self.assertEqual(r.status_code, 400)

    # --- attack demonstration endpoints ----------------------------------------------------------
    def test_attack_endpoints(self):
        self.send("HTTPS")
        t = requests.post(f"{BASE}/api/simulate/tamper", timeout=10).json()
        self.assertFalse(t["experiment"]["decryption_attempted"])
        rp = requests.post(f"{BASE}/api/simulate/replay", timeout=10).json()
        self.assertTrue(rp["experiment"]["replay_blocked"])
        m = requests.post(f"{BASE}/api/simulate/mitm", timeout=30).json()
        self.assertTrue(m["authenticated_dh"]["attack_prevented"])
        tls = m["tls_certificate_verification"]
        self.assertFalse(tls["success"])
        self.assertEqual(tls["error_type"], "SSL_CERT_VERIFICATION_ERROR")
        e = requests.post(f"{BASE}/api/simulate/eavesdrop", timeout=10).json()
        self.assertTrue(e["comparison"]["plaintext_experiment"]["payload_readable"])
        self.assertFalse(e["comparison"]["encrypted_experiment"]["payload_readable"])

    # --- responses must not leak secrets -----------------------------------------------------------
    def test_api_responses_do_not_expose_keys(self):
        s = cyber_app.CURRENT_SESSION
        blob = requests.get(BASE + "/api/session", timeout=10).text + str(self.send("HTTPS")["crypto_summary"])
        for secret in (s.aes_key.hex(), s.hmac_key.hex(), s.shared_secret.hex()):
            self.assertNotIn(secret, blob)

    def test_new_session_resets_replay_cache(self):
        self.send("HTTP")
        r = requests.post(f"{BASE}/api/session/new", timeout=30).json()
        self.assertEqual(r["status"], "success")
        self.assertEqual(cyber_app.GLOBAL_REPLAY_ENGINE.get_cache_size(), 0)


if __name__ == "__main__":
    unittest.main()
