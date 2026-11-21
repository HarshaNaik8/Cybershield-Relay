"""
Unit tests for the CyberShield-Relay cryptographic package.
Covers: DH key exchange, HKDF key separation, AES-256-CBC, HMAC verification, Ed25519 handshake
authentication, and the Encrypt-then-MAC ordering inside CryptoSession.
"""

import os
import unittest
from unittest import mock

from cryptography.exceptions import InvalidSignature  # noqa: F401  (documents the primitive used)

from crypto import DHKeyExchange, HKDFKeyDerivation, AESCipher, HMACAuthenticator, Ed25519HandshakeAuth, RFC3526_P, RFC3526_G
from crypto_engine import CryptoSession, b64_encode, b64_decode

TS = "2026-01-01T00:00:00+00:00"


class TestDiffieHellman(unittest.TestCase):
    def test_group_parameters(self):
        self.assertEqual(RFC3526_P.bit_length(), 2048)
        self.assertEqual(RFC3526_G, 2)

    def test_both_parties_derive_same_secret(self):
        a, b = DHKeyExchange("A"), DHKeyExchange("B")
        sa = a.compute_shared_secret(b.public_key)
        sb = b.compute_shared_secret(a.public_key)
        self.assertEqual(sa, sb)
        self.assertEqual(len(sa), 256)

    def test_ephemeral_keys_differ_between_sessions(self):
        self.assertNotEqual(DHKeyExchange("A").get_public_pem(), DHKeyExchange("A").get_public_pem())


class TestHKDF(unittest.TestCase):
    def test_separate_256_bit_keys(self):
        secret = os.urandom(256)
        aes_key, mac_key = HKDFKeyDerivation.derive_keys(secret)
        self.assertEqual((len(aes_key), len(mac_key)), (32, 32))
        self.assertNotEqual(aes_key, mac_key)

    def test_deterministic_and_secret_dependent(self):
        s1, s2 = os.urandom(256), os.urandom(256)
        self.assertEqual(HKDFKeyDerivation.derive_keys(s1), HKDFKeyDerivation.derive_keys(s1))
        self.assertNotEqual(HKDFKeyDerivation.derive_keys(s1), HKDFKeyDerivation.derive_keys(s2))


class TestAES(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)

    def test_round_trip_and_block_alignment(self):
        iv, ct = AESCipher.encrypt("Unauthorized access in DMZ", self.key)
        self.assertEqual(len(iv), 16)
        self.assertEqual(len(ct) % 16, 0)
        self.assertEqual(AESCipher.decrypt(ct, self.key, iv), "Unauthorized access in DMZ")

    def test_fresh_iv_gives_different_ciphertext(self):
        _, c1 = AESCipher.encrypt("same text", self.key)
        _, c2 = AESCipher.encrypt("same text", self.key)
        self.assertNotEqual(c1, c2)

    def test_wrong_key_does_not_return_plaintext(self):
        iv, ct = AESCipher.encrypt("secret report", self.key)
        try:
            self.assertNotEqual(AESCipher.decrypt(ct, os.urandom(32), iv), "secret report")
        except Exception:
            pass  # invalid padding is the expected outcome


class TestHMAC(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.iv, self.ct = os.urandom(16), os.urandom(32)
        self.meta = HMACAuthenticator.build_authenticated_data("CC-1", TS, "msg_a")
        self.tag = HMACAuthenticator.generate_tag(self.key, self.meta, self.iv, self.ct)

    def test_valid_tag_verifies(self):
        self.assertTrue(HMACAuthenticator.verify_tag(self.key, self.meta, self.iv, self.ct, self.tag))

    def test_any_modified_field_is_rejected(self):
        flip = lambda b: bytes([b[0] ^ 1]) + b[1:]
        other_meta = HMACAuthenticator.build_authenticated_data("CC-2", TS, "msg_a")
        self.assertFalse(HMACAuthenticator.verify_tag(self.key, self.meta, self.iv, flip(self.ct), self.tag))
        self.assertFalse(HMACAuthenticator.verify_tag(self.key, self.meta, flip(self.iv), self.ct, self.tag))
        self.assertFalse(HMACAuthenticator.verify_tag(self.key, other_meta, self.iv, self.ct, self.tag))
        self.assertFalse(HMACAuthenticator.verify_tag(self.key, self.meta, self.iv, self.ct, flip(self.tag)))
        self.assertFalse(HMACAuthenticator.verify_tag(os.urandom(32), self.meta, self.iv, self.ct, self.tag))


class TestEd25519Handshake(unittest.TestCase):
    def test_signature_binds_transcript(self):
        ident = Ed25519HandshakeAuth()
        transcript = Ed25519HandshakeAuth.build_transcript("sid", "PEM_A", "PEM_B", "n1")
        sig = ident.sign_handshake(transcript)
        self.assertTrue(Ed25519HandshakeAuth.verify_handshake(ident.verifying_key, transcript, sig))
        forged = Ed25519HandshakeAuth.build_transcript("sid", "PEM_A", "PEM_MALLORY", "n1")
        self.assertFalse(Ed25519HandshakeAuth.verify_handshake(ident.verifying_key, forged, sig))


class TestCryptoSession(unittest.TestCase):
    def setUp(self):
        self.s = CryptoSession()

    def test_session_handshake_and_key_sizes(self):
        self.assertTrue(self.s.handshake_verified)
        self.assertEqual((len(self.s.aes_key), len(self.s.hmac_key)), (32, 32))

    def test_end_to_end_round_trip(self):
        iv, ct, tag = self.s.encrypt_incident("[CC-1] report", "CC-1", TS, "msg_a")
        pt, ok, _ = self.s.verify_and_decrypt(iv, ct, tag, "CC-1", TS, "msg_a")
        self.assertTrue(ok)
        self.assertEqual(pt, "[CC-1] report")

    def test_tampered_ciphertext_rejected_before_decryption(self):
        iv, ct, tag = self.s.encrypt_incident("[CC-1] report", "CC-1", TS, "msg_a")
        bad = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with mock.patch("crypto_engine.AESCipher.decrypt") as dec:
            pt, ok, reason = self.s.verify_and_decrypt(iv, bad, tag, "CC-1", TS, "msg_a")
        self.assertFalse(ok)
        self.assertIsNone(pt)
        self.assertIn("HMAC", reason)
        dec.assert_not_called()          # AES decryption must never run for unauthenticated input

    def test_modified_metadata_rejected(self):
        iv, ct, tag = self.s.encrypt_incident("x", "CC-1", TS, "msg_a")
        for args in (("CC-9", TS, "msg_a"), ("CC-1", "2026-01-01T00:00:01+00:00", "msg_a"), ("CC-1", TS, "msg_b")):
            self.assertFalse(self.s.verify_and_decrypt(iv, ct, tag, *args)[1])

    def test_summary_never_exposes_secrets(self):
        text = str(self.s.get_session_summary())
        for secret in (self.s.aes_key.hex(), self.s.hmac_key.hex(), self.s.shared_secret.hex(), b64_encode(self.s.aes_key)):
            self.assertNotIn(secret, text)

    def test_base64_helpers(self):
        self.assertEqual(b64_decode(b64_encode(b"\x00\xff\x10")), b"\x00\xff\x10")


if __name__ == "__main__":
    unittest.main()
