"""
Unit tests for the controlled attack demonstrations (security package) and the replay-protection engine.
"""

import datetime
import os
import unittest

from crypto_engine import CryptoSession, b64_encode
from security.eavesdropping import EavesdroppingExperiment
from security.mitm_simulation import MITMSimulation
from security.tampering import TamperingExperiment
from network.replay_protection import ReplayProtectionEngine


def make_packet(session, nonce=None, ts=None, message="[CC-9] gateway compromised"):
    nonce = nonce or "msg_" + os.urandom(6).hex()
    ts = ts or datetime.datetime.now(datetime.timezone.utc).isoformat()
    iv, ct, tag = session.encrypt_incident(message, "CC-9", ts, nonce)
    return {"incident_id": "CC-9", "timestamp": ts, "nonce": nonce, "iv": b64_encode(iv),
            "ciphertext": b64_encode(ct), "hmac": b64_encode(tag), "protocol": "HTTP"}


class TestEavesdropping(unittest.TestCase):
    def test_plaintext_visible_but_encrypted_hidden(self):
        s = CryptoSession()
        msg = "TOP SECRET: dispatch to SOC level 3"
        res = EavesdroppingExperiment.run_comparison(sample_message=msg, incident_id="CC-1", session=s)
        self.assertTrue(res["plaintext_experiment"]["payload_readable"])
        self.assertIn(msg, res["plaintext_experiment"]["wire_payload_sample"])
        self.assertFalse(res["encrypted_experiment"]["payload_readable"])
        self.assertNotIn(msg, str(res["encrypted_experiment"]))
        self.assertGreater(res["comparison_metrics"]["overhead_bytes"], 0)


class TestMITM(unittest.TestCase):
    def test_unauthenticated_dh_is_compromised(self):
        res = MITMSimulation.simulate_unauthenticated_dh_mitm()
        self.assertEqual(res["attack_outcome"], "COMPROMISED")
        keys = res["keys_established"]
        self.assertNotEqual(keys["mallory_shared_with_alice"], keys["mallory_shared_with_bob"])

    def test_ed25519_handshake_blocks_key_substitution(self):
        res = MITMSimulation.simulate_authenticated_dh_mitm()
        self.assertTrue(res["legitimate_verification"])
        self.assertFalse(res["mitm_attack_verification"])
        self.assertTrue(res["attack_prevented"])


class TestTampering(unittest.TestCase):
    def test_bit_flip_is_rejected_without_decryption(self):
        s = CryptoSession()
        res = TamperingExperiment.simulate_tampering(make_packet(s), session=s)
        self.assertNotEqual(res["original_ciphertext"], res["tampered_ciphertext"])
        self.assertFalse(res["hmac_verified"])
        self.assertFalse(res["decryption_attempted"])
        self.assertEqual(res["receiver_action"], "REJECT_AND_DROP")


class TestReplayEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ReplayProtectionEngine()
        self.now = datetime.datetime.now(datetime.timezone.utc)

    def test_first_use_accepted_second_rejected(self):
        ts = self.now.isoformat()
        self.assertEqual(self.engine.validate_packet("n1", ts)[1], "FRESH")
        self.assertEqual(self.engine.validate_packet("n1", ts)[1], "REPLAY_DETECTED")
        self.assertEqual(self.engine.get_cache_size(), 1)

    def test_freshness_window_edges(self):
        old = (self.now - datetime.timedelta(seconds=290)).isoformat()
        stale = (self.now - datetime.timedelta(seconds=310)).isoformat()
        future = (self.now + datetime.timedelta(seconds=310)).isoformat()
        self.assertEqual(self.engine.validate_packet("a", old)[1], "FRESH")
        self.assertEqual(self.engine.validate_packet("b", stale)[1], "TIMESTAMP_EXPIRED")
        self.assertEqual(self.engine.validate_packet("c", future)[1], "TIMESTAMP_EXPIRED")

    def test_malformed_and_missing_fields(self):
        self.assertEqual(self.engine.validate_packet("x", "not-a-time")[1], "MALFORMED_TIMESTAMP")
        self.assertEqual(self.engine.validate_packet("", self.now.isoformat())[1], "MISSING_NONCE")
        self.assertEqual(self.engine.validate_packet("y", "")[1], "MISSING_TIMESTAMP")

    def test_reset_clears_cache(self):
        self.engine.validate_packet("n", self.now.isoformat())
        self.engine.reset()
        self.assertEqual(self.engine.get_cache_size(), 0)


if __name__ == "__main__":
    unittest.main()
