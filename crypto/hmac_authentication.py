"""
HMAC-SHA256 Authenticated Encryption (Encrypt-then-MAC)
Computes and verifies cryptographic authentication tags over
message metadata, IV, and ciphertext using constant-time comparison.
"""

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature


class HMACAuthenticator:
    """
    Encrypt-then-MAC authenticator with metadata binding.
    """

    @staticmethod
    def build_authenticated_data(incident_id: str, timestamp: str, nonce: str) -> bytes:
        """
        Formats metadata to bind into HMAC tag to prevent metadata alteration.
        """
        return f"{incident_id}|{timestamp}|{nonce}".encode("utf-8")

    @classmethod
    def generate_tag(cls, key: bytes, auth_data: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """
        Generates HMAC-SHA256 tag over (auth_data || IV || ciphertext).
        """
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(auth_data)
        h.update(iv)
        h.update(ciphertext)
        return h.finalize()

    @classmethod
    def verify_tag(cls, key: bytes, auth_data: bytes, iv: bytes,
                   ciphertext: bytes, expected_tag: bytes) -> bool:
        """
        Verifies HMAC-SHA256 tag using constant-time comparison.
        Returns True if valid, False if tampered or invalid.
        """
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(auth_data)
        h.update(iv)
        h.update(ciphertext)
        try:
            h.verify(expected_tag)
            return True
        except (InvalidSignature, Exception):
            return False
