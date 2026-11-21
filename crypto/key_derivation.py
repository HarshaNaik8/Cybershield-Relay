"""
Key Derivation Function (HKDF-SHA256, RFC 5869)
Extracts and expands the Diffie-Hellman shared secret into distinct,
cryptographically independent symmetric keys for AES-256 and HMAC-SHA256.
"""

from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_SALT = b"CyberShield-Relay-Salt-v1"
DEFAULT_INFO = b"CyberShield-Relay-KeyDerivation"


class HKDFKeyDerivation:
    """
    Derives independent keys using HKDF-SHA256 with domain separation.
    """

    @staticmethod
    def derive_keys(shared_secret: bytes, salt: bytes = DEFAULT_SALT,
                    info: bytes = DEFAULT_INFO) -> Tuple[bytes, bytes]:
        """
        Derives two 32-byte (256-bit) keys from the shared secret:
        1. AES-256 Encryption Key
        2. HMAC-SHA256 Authentication Key
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            info=info,
        )
        derived = hkdf.derive(shared_secret)
        aes_key = derived[:32]
        hmac_key = derived[32:]
        return aes_key, hmac_key

    @staticmethod
    def compute_fingerprint(key: bytes) -> str:
        """Computes SHA-256 fingerprint of a key for safe identification."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(key)
        hex_digest = digest.finalize().hex()
        return ":".join(hex_digest[i:i+2] for i in range(0, len(hex_digest), 2))
