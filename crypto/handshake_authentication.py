"""
Ed25519 Handshake Digital Signature & Authentication
Protects the Diffie-Hellman key exchange from Man-in-the-Middle (MITM) attacks
by cryptographically signing the handshake transcript with an identity key.
"""

from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class Ed25519HandshakeAuth:
    """
    Provides digital signatures for the Diffie-Hellman handshake transcript.
    Officer B (Server) possesses a long-term Ed25519 signing key.
    Officer A (Client) pins Officer B's Ed25519 verifying key.
    """

    def __init__(self, private_key: ed25519.Ed25519PrivateKey = None):
        if private_key:
            self.signing_key = private_key
        else:
            self.signing_key = ed25519.Ed25519PrivateKey.generate()
        self.verifying_key = self.signing_key.public_key()

    def get_verifying_key_bytes(self) -> bytes:
        """Returns the public verifying key as raw 32 bytes."""
        return self.verifying_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def get_verifying_key_hex(self) -> str:
        """Returns the verifying key as a hex string."""
        return self.get_verifying_key_bytes().hex()

    @staticmethod
    def build_transcript(session_id: str, officer_a_pub_pem: str,
                         officer_b_pub_pem: str, nonce: str) -> bytes:
        """
        Constructs the authoritative transcript string that binds:
        - Session Identifier
        - Officer A Public Key (Sender)
        - Officer B Public Key (Receiver)
        - Handshake Nonce (prevents replay of past handshakes)
        """
        # Canonical normalization
        clean_a = officer_a_pub_pem.strip().replace("\r\n", "\n")
        clean_b = officer_b_pub_pem.strip().replace("\r\n", "\n")
        transcript = f"CYBERSHIELD_DH_TRANSCRIPT_V1|{session_id}|{clean_a}|{clean_b}|{nonce}"
        return transcript.encode("utf-8")

    def sign_handshake(self, transcript_bytes: bytes) -> bytes:
        """Signs the DH handshake transcript with the Ed25519 private key."""
        return self.signing_key.sign(transcript_bytes)

    @staticmethod
    def verify_handshake(verifying_key: ed25519.Ed25519PublicKey,
                         transcript_bytes: bytes, signature: bytes) -> bool:
        """
        Verifies that the handshake transcript was legitimately signed
        by the trusted private key holder.
        """
        try:
            verifying_key.verify(signature, transcript_bytes)
            return True
        except (InvalidSignature, Exception):
            return False

    @staticmethod
    def load_verifying_key(raw_bytes: bytes) -> ed25519.Ed25519PublicKey:
        """Loads an Ed25519 public key from 32 raw bytes."""
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)


# Singleton identity for Officer B server (provisioned/pinned)
OFFICER_B_IDENTITY = Ed25519HandshakeAuth()
