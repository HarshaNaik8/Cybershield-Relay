"""
AES-256-CBC Encryption & Decryption
Implements 256-bit AES in Cipher Block Chaining mode with PKCS#7 padding.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

BLOCK_SIZE_BITS = 128
BLOCK_SIZE_BYTES = 16


class AESCipher:
    """
    AES-256-CBC cipher with PKCS#7 padding and secure random IV generation.
    """

    @staticmethod
    def encrypt(plaintext: str, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        """
        Encrypts plaintext string using AES-256-CBC.
        Generates a fresh 16-byte random IV if none is provided.
        Returns: (iv, ciphertext)
        """
        if iv is None:
            iv = os.urandom(BLOCK_SIZE_BYTES)

        # Pad plaintext to 16-byte block boundary using PKCS#7
        padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
        padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()

        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv, ciphertext

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> str:
        """
        Decrypts AES-256-CBC ciphertext and removes PKCS#7 padding.
        Raises ValueError if padding is invalid.
        """
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad and validate PKCS#7
        unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
        plaintext_bytes = unpadder.update(padded_data) + unpadder.finalize()

        return plaintext_bytes.decode("utf-8")
