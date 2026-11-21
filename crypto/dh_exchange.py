"""
Diffie-Hellman Key Exchange (RFC 3526 2048-bit MODP Group 14)
Implements ephemeral key pair generation, public key serialization,
and shared secret computation.
"""

import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# RFC 3526 2048-bit MODP Group 14 safe prime and generator
RFC3526_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
RFC3526_P = int(RFC3526_P_HEX, 16)
RFC3526_G = 2

# Standard parameters instance
DH_PARAMETERS = dh.DHParameterNumbers(RFC3526_P, RFC3526_G).parameters()


class DHKeyExchange:
    """
    Manages an ephemeral Diffie-Hellman endpoint.
    Generates private/public key pairs and performs key exchange.
    """

    def __init__(self, role: str = "Endpoint"):
        self.role = role
        self.parameters = DH_PARAMETERS
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self) -> bytes:
        """Serializes the public key to SubjectPublicKeyInfo PEM bytes."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_public_pem(self) -> str:
        """Returns the public key as a PEM string."""
        return self.get_public_bytes().decode("utf-8")

    def get_public_numbers_hex(self) -> str:
        """Returns the public value y = g^x mod p as a hexadecimal string."""
        pn = self.public_key.public_numbers()
        return format(pn.y, "x")

    def compute_shared_secret(self, peer_public_key) -> bytes:
        """
        Computes the shared secret using the peer's public key.
        Returns 256 bytes (2048 bits).
        """
        return self.private_key.exchange(peer_public_key)

    @staticmethod
    def load_public_key_from_pem(pem_bytes: bytes):
        """Loads a public key from PEM bytes."""
        return serialization.load_pem_public_key(pem_bytes)
