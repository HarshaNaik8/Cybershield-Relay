"""
CyberShield Relay - Cryptographic Engine Facade
Provides backward-compatible interface and session orchestration,
delegating to the modular crypto package.
"""

import os
import base64
from typing import Dict, Any, Tuple

from crypto.dh_exchange import DHKeyExchange, RFC3526_P, RFC3526_G, DH_PARAMETERS
from crypto.key_derivation import HKDFKeyDerivation
from crypto.aes_encryption import AESCipher
from crypto.hmac_authentication import HMACAuthenticator
from crypto.handshake_authentication import Ed25519HandshakeAuth, OFFICER_B_IDENTITY


def b64_encode(data: bytes) -> str:
    """Encodes bytes to base64 string."""
    return base64.b64encode(data).decode("utf-8")


def b64_decode(data: str) -> bytes:
    """Decodes base64 string to bytes."""
    return base64.b64decode(data.encode("utf-8"))


class CryptoSession:
    """
    Orchestrates an authenticated cryptographic session between Officer A and Officer B.
    Integrates:
    - RFC 3526 2048-bit MODP DH Key Exchange
    - Ed25519 Handshake Signature (MITM prevention)
    - HKDF-SHA256 Key Derivation (AES + HMAC keys)
    - AES-256-CBC Encryption (PKCS#7)
    - HMAC-SHA256 Authenticated Encryption (Encrypt-then-MAC with metadata)
    """

    def __init__(self, authenticate_handshake: bool = True):
        self.session_id = base64.b64encode(os.urandom(8)).decode("utf-8")
        self.authenticate_handshake = authenticate_handshake

        # Ephemeral DH endpoints
        self.officer_a_dh = DHKeyExchange("Officer A")
        self.officer_b_dh = DHKeyExchange("Officer B")

        # Public keys
        self.officer_a_public = self.officer_a_dh.public_key
        self.officer_b_public = self.officer_b_dh.public_key

        # Handshake Authentication via Ed25519
        self.server_identity = OFFICER_B_IDENTITY
        self.handshake_nonce = os.urandom(8).hex()
        self.handshake_transcript = Ed25519HandshakeAuth.build_transcript(
            self.session_id,
            self.officer_a_dh.get_public_pem(),
            self.officer_b_dh.get_public_pem(),
            self.handshake_nonce,
        )
        self.handshake_signature = self.server_identity.sign_handshake(self.handshake_transcript)

        # Verify handshake if authentication is enabled
        self.handshake_verified = Ed25519HandshakeAuth.verify_handshake(
            self.server_identity.verifying_key,
            self.handshake_transcript,
            self.handshake_signature,
        )

        # Shared Secret
        self.shared_secret_a = self.officer_a_dh.compute_shared_secret(self.officer_b_public)
        self.shared_secret_b = self.officer_b_dh.compute_shared_secret(self.officer_a_public)
        assert self.shared_secret_a == self.shared_secret_b, "DH shared secret mismatch!"
        self.shared_secret = self.shared_secret_a

        # Key Derivation (AES-256 & HMAC-SHA256)
        self.aes_key, self.hmac_key = HKDFKeyDerivation.derive_keys(self.shared_secret)

    def get_session_summary(self) -> Dict[str, Any]:
        """
        Returns safe session summary for UI inspection.
        Never exposes raw private keys, AES keys, HMAC keys, or raw shared secrets.
        """
        a_pem = self.officer_a_dh.get_public_pem()
        b_pem = self.officer_b_dh.get_public_pem()

        shared_fp = HKDFKeyDerivation.compute_fingerprint(self.shared_secret)
        aes_fp = HKDFKeyDerivation.compute_fingerprint(self.aes_key)
        hmac_fp = HKDFKeyDerivation.compute_fingerprint(self.hmac_key)

        return {
            "session_id": self.session_id,
            "dh_group": "RFC 3526 MODP Group 14 (2048-bit)",
            "dh_generator": RFC3526_G,
            "dh_prime_bits": 2048,
            "officer_a_public_pem": a_pem,
            "officer_a_public_preview": a_pem.splitlines()[1][:32] + "...",
            "officer_b_public_pem": b_pem,
            "officer_b_public_preview": b_pem.splitlines()[1][:32] + "...",
            "shared_secret_length_bytes": len(self.shared_secret),
            "shared_secret_fingerprint": shared_fp[:17] + "..." + shared_fp[-11:],
            "shared_secret_redacted": "<REDACTED 2048-BIT DH SECRET>",
            "kdf_algorithm": "HKDF-SHA256",
            "aes_key_length_bits": 256,
            "aes_key_fingerprint": aes_fp[:17] + "..." + aes_fp[-11:],
            "aes_key_redacted": "<REDACTED 256-BIT AES KEY>",
            "hmac_key_length_bits": 256,
            "hmac_key_fingerprint": hmac_fp[:17] + "..." + hmac_fp[-11:],
            "hmac_key_redacted": "<REDACTED 256-BIT HMAC KEY>",
            "cipher_suite": "AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)",
            "handshake_auth_algorithm": "Ed25519 (256-bit Digital Signature)",
            "handshake_verified": self.handshake_verified,
            "server_verifying_key_hex": self.server_identity.get_verifying_key_hex()[:24] + "...",
            "handshake_signature_hex": self.handshake_signature.hex()[:24] + "...",
        }

    def encrypt_incident(self, message: str, incident_id: str,
                         timestamp: str, nonce: str) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypts incident message with AES-256-CBC and generates HMAC-SHA256 tag.
        Returns: (iv, ciphertext, hmac_tag)
        """
        iv, ciphertext = AESCipher.encrypt(message, self.aes_key)
        auth_data = HMACAuthenticator.build_authenticated_data(incident_id, timestamp, nonce)
        hmac_tag = HMACAuthenticator.generate_tag(self.hmac_key, auth_data, iv, ciphertext)
        return iv, ciphertext, hmac_tag

    def verify_and_decrypt(self, iv: bytes, ciphertext: bytes, hmac_tag: bytes,
                           incident_id: str, timestamp: str, nonce: str) -> Tuple[str, bool, str]:
        """
        Verifies HMAC-SHA256 tag in constant time before decryption.
        If valid, decrypts AES-256-CBC ciphertext and unpads PKCS#7.
        Returns: (plaintext_or_none, is_valid, status_reason)
        """
        auth_data = HMACAuthenticator.build_authenticated_data(incident_id, timestamp, nonce)

        # 1. Constant-time HMAC verification
        is_authentic = HMACAuthenticator.verify_tag(
            self.hmac_key, auth_data, iv, ciphertext, hmac_tag
        )
        if not is_authentic:
            return None, False, "HMAC-SHA256 verification failed: Payload or metadata was modified or forged."

        # 2. Decrypt with AES-256-CBC
        try:
            plaintext = AESCipher.decrypt(ciphertext, self.aes_key, iv)
            return plaintext, True, "Message integrity and authenticity verified. Decryption successful."
        except Exception as e:
            return None, False, f"Decryption/unpadding error: {str(e)}"
