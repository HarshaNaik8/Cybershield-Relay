"""
Cryptographic Performance Benchmarking
Measures exact wall-clock latency for every cryptographic primitive:
DH key exchange, Ed25519 signatures, HKDF, AES-256-CBC, and HMAC-SHA256.
Uses high-precision monotonic timing (time.perf_counter_ns).
"""

import time
from typing import Dict, Any

from crypto import (
    DHKeyExchange, HKDFKeyDerivation, AESCipher,
    HMACAuthenticator, Ed25519HandshakeAuth
)


class CryptoBenchmark:
    """
    Executes real high-precision benchmarking of all cryptographic operations.
    """

    @classmethod
    def run_benchmark(cls, sample_message: str = "Confidential incident intelligence payload for benchmark.") -> Dict[str, Any]:
        """
        Runs and times every cryptographic step. Returns metrics in microseconds and milliseconds.
        """
        # 1. DH Key Pair Generation
        t0 = time.perf_counter_ns()
        alice = DHKeyExchange("Alice")
        bob = DHKeyExchange("Bob")
        t1 = time.perf_counter_ns()
        dh_keygen_us = (t1 - t0) / 2000.0  # per endpoint

        # 2. DH Shared Secret Computation
        t0 = time.perf_counter_ns()
        shared_secret = alice.compute_shared_secret(bob.public_key)
        t1 = time.perf_counter_ns()
        dh_exchange_us = (t1 - t0) / 1000.0

        # 3. Ed25519 Handshake Signature
        server_auth = Ed25519HandshakeAuth()
        transcript = Ed25519HandshakeAuth.build_transcript("sess_bench", alice.get_public_pem(), bob.get_public_pem(), "bench_nonce")
        t0 = time.perf_counter_ns()
        sig = server_auth.sign_handshake(transcript)
        t1 = time.perf_counter_ns()
        ed25519_sign_us = (t1 - t0) / 1000.0

        # 4. Ed25519 Verification
        t0 = time.perf_counter_ns()
        Ed25519HandshakeAuth.verify_handshake(server_auth.verifying_key, transcript, sig)
        t1 = time.perf_counter_ns()
        ed25519_verify_us = (t1 - t0) / 1000.0

        # 5. HKDF Key Derivation
        t0 = time.perf_counter_ns()
        aes_k, hmac_k = HKDFKeyDerivation.derive_keys(shared_secret)
        t1 = time.perf_counter_ns()
        hkdf_us = (t1 - t0) / 1000.0

        # 6. AES-256-CBC Encryption
        t0 = time.perf_counter_ns()
        iv, ct = AESCipher.encrypt(sample_message, aes_k)
        t1 = time.perf_counter_ns()
        aes_enc_us = (t1 - t0) / 1000.0

        # 7. HMAC-SHA256 Generation
        auth_data = HMACAuthenticator.build_authenticated_data("INC-BENCH", "2026-01-01", "bench_nonce")
        t0 = time.perf_counter_ns()
        tag = HMACAuthenticator.generate_tag(hmac_k, auth_data, iv, ct)
        t1 = time.perf_counter_ns()
        hmac_gen_us = (t1 - t0) / 1000.0

        # 8. HMAC-SHA256 Verification
        t0 = time.perf_counter_ns()
        HMACAuthenticator.verify_tag(hmac_k, auth_data, iv, ct, tag)
        t1 = time.perf_counter_ns()
        hmac_verify_us = (t1 - t0) / 1000.0

        # 9. AES-256-CBC Decryption
        t0 = time.perf_counter_ns()
        AESCipher.decrypt(ct, aes_k, iv)
        t1 = time.perf_counter_ns()
        aes_dec_us = (t1 - t0) / 1000.0

        total_crypto_pipeline_ms = (
            dh_keygen_us + dh_exchange_us + ed25519_sign_us + ed25519_verify_us +
            hkdf_us + aes_enc_us + hmac_gen_us + hmac_verify_us + aes_dec_us
        ) / 1000.0

        return {
            "dh_keygen_ms": round(dh_keygen_us / 1000.0, 3),
            "dh_shared_secret_ms": round(dh_exchange_us / 1000.0, 3),
            "ed25519_sign_ms": round(ed25519_sign_us / 1000.0, 3),
            "ed25519_verify_ms": round(ed25519_verify_us / 1000.0, 3),
            "hkdf_derivation_ms": round(hkdf_us / 1000.0, 3),
            "aes_encryption_ms": round(aes_enc_us / 1000.0, 3),
            "hmac_generation_ms": round(hmac_gen_us / 1000.0, 3),
            "hmac_verification_ms": round(hmac_verify_us / 1000.0, 3),
            "aes_decryption_ms": round(aes_dec_us / 1000.0, 3),
            "total_crypto_pipeline_ms": round(total_crypto_pipeline_ms, 3),
            "payload_length_bytes": len(sample_message.encode("utf-8")),
            "ciphertext_length_bytes": len(ct),
        }
