"""
CyberShield Relay - Cryptographic Module
Provides:
- Diffie-Hellman Key Exchange (RFC 3526 2048-bit MODP Group 14)
- HKDF-SHA256 Key Derivation (RFC 5869)
- AES-256-CBC Encryption & Decryption with PKCS#7 Padding
- HMAC-SHA256 Authenticated Encryption (Encrypt-then-MAC)
- Ed25519 Handshake Digital Signatures for MITM Prevention
"""

from .dh_exchange import DHKeyExchange, RFC3526_P, RFC3526_G
from .key_derivation import HKDFKeyDerivation
from .aes_encryption import AESCipher
from .hmac_authentication import HMACAuthenticator
from .handshake_authentication import Ed25519HandshakeAuth

__all__ = [
    "DHKeyExchange",
    "RFC3526_P",
    "RFC3526_G",
    "HKDFKeyDerivation",
    "AESCipher",
    "HMACAuthenticator",
    "Ed25519HandshakeAuth",
]
