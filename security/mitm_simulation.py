"""
Man-in-the-Middle (MITM) Interception & Handshake Authentication Simulation
Demonstrates:
1. The vulnerability of unauthenticated Diffie-Hellman to key-substitution attacks.
2. How Ed25519 digital signatures on the DH transcript prevent MITM attacks.
3. How an interception proxy manipulates traffic and causes receiver rejection.
"""

from typing import Dict, Any, Optional
from crypto.dh_exchange import DHKeyExchange
from crypto.handshake_authentication import Ed25519HandshakeAuth, OFFICER_B_IDENTITY
from network.interception_proxy import GLOBAL_PROXY
from .security_events import get_event_manager


class MITMSimulation:
    """
    Simulates Man-in-the-Middle scenarios and evaluates cryptographic defenses.
    """

    @classmethod
    def simulate_unauthenticated_dh_mitm(cls) -> Dict[str, Any]:
        """
        Simulates Mallory intercepting an unauthenticated DH key exchange.
        Mallory substitutes her own public keys and derives independent session keys.
        """
        event_mgr = get_event_manager()

        # Legitimate endpoints
        alice = DHKeyExchange("Officer A (Alice)")
        bob = DHKeyExchange("Officer B (Bob)")

        # Adversary Mallory
        mallory_to_alice = DHKeyExchange("Mallory (Attacker to Alice)")
        mallory_to_bob = DHKeyExchange("Mallory (Attacker to Bob)")

        # Mallory intercepts:
        # Instead of Alice getting Bob's key, Alice receives Mallory's key
        key_alice_mallory = alice.compute_shared_secret(mallory_to_alice.public_key)
        key_mallory_alice = mallory_to_alice.compute_shared_secret(alice.public_key)
        assert key_alice_mallory == key_mallory_alice

        # Instead of Bob getting Alice's key, Bob receives Mallory's key
        key_bob_mallory = bob.compute_shared_secret(mallory_to_bob.public_key)
        key_mallory_bob = mallory_to_bob.compute_shared_secret(bob.public_key)
        assert key_bob_mallory == key_mallory_bob

        event_mgr.log_event(
            "ATTACK",
            "Unauthenticated DH MITM Attack Succeeded (Demonstration)",
            "Mallory intercepted public keys and established split keys K_AM and K_MB. Traffic can be decrypted.",
            "CRITICAL",
        )

        return {
            "attack_type": "Unauthenticated Diffie-Hellman Key Substitution (MITM)",
            "vulnerability": (
                "Finite-field Diffie-Hellman guarantees confidentiality against passive eavesdroppers, "
                "but provides zero authentication. An active adversary can replace public values A and B, "
                "establishing two independent shared secrets."
            ),
            "attack_outcome": "COMPROMISED",
            "keys_established": {
                "alice_thinks_she_shares_with_bob": key_alice_mallory.hex()[:16] + "...",
                "mallory_shared_with_alice": key_mallory_alice.hex()[:16] + "...",
                "mallory_shared_with_bob": key_mallory_bob.hex()[:16] + "...",
                "bob_thinks_he_shares_with_alice": key_bob_mallory.hex()[:16] + "...",
            },
            "defense_recommendation": (
                "Cryptographically bind the DH transcript to verified endpoint identities using digital signatures (Ed25519) "
                "or public-key certificates (TLS X.509)."
            ),
        }

    @classmethod
    def simulate_authenticated_dh_mitm(cls) -> Dict[str, Any]:
        """
        Simulates Mallory attempting to substitute public keys in an Ed25519-authenticated DH exchange.
        Officer A validates the signature against Officer B's pinned key.
        Because Mallory lacks Officer B's Ed25519 private key, the signature verification fails!
        """
        event_mgr = get_event_manager()

        alice = DHKeyExchange("Officer A (Alice)")
        bob = DHKeyExchange("Officer B (Bob)")
        bob_identity = OFFICER_B_IDENTITY

        # Legitimate transcript and signature from Bob
        session_id = "sess_demo_auth"
        nonce = "nonce_auth_123"
        valid_transcript = Ed25519HandshakeAuth.build_transcript(
            session_id, alice.get_public_pem(), bob.get_public_pem(), nonce
        )
        valid_signature = bob_identity.sign_handshake(valid_transcript)

        # Mallory attempts to replace Bob's public key with Mallory's key
        mallory = DHKeyExchange("Mallory (Attacker)")
        tampered_transcript = Ed25519HandshakeAuth.build_transcript(
            session_id, alice.get_public_pem(), mallory.get_public_pem(), nonce
        )

        # Alice verifies using Bob's pinned verifying key:
        # Case 1: Valid transcript signed by Bob -> SUCCEEDS
        legit_check = Ed25519HandshakeAuth.verify_handshake(
            bob_identity.verifying_key, valid_transcript, valid_signature
        )

        # Case 2: Mallory's substituted key with Bob's original signature -> FAILS!
        mitm_check = Ed25519HandshakeAuth.verify_handshake(
            bob_identity.verifying_key, tampered_transcript, valid_signature
        )

        event_mgr.log_event(
            "ATTACK",
            "MITM Attack Blocked by Ed25519 Handshake Signature",
            "Mallory's substituted DH public key broke the Ed25519 signature. Officer A rejected the handshake.",
            "HIGH",
        )

        return {
            "attack_type": "MITM on Authenticated Diffie-Hellman Handshake",
            "defense_mechanism": "Ed25519 (256-bit Edwards-curve Digital Signature)",
            "pinned_verifying_key_hex": bob_identity.get_verifying_key_hex()[:24] + "...",
            "legitimate_verification": legit_check,
            "mitm_attack_verification": mitm_check,
            "attack_prevented": (not mitm_check),
            "outcome": "MITM_BLOCKED",
            "explanation": (
                "Officer A verified the handshake transcript with Officer B's pinned Ed25519 public key. "
                "Because Mallory does not possess Officer B's Ed25519 private signing key, "
                "any modification to the public key or session parameters invalidates the signature. "
                "The handshake is aborted before any symmetric keys are derived or data is sent."
            ),
        }

    @classmethod
    def test_interception_proxy(cls, packet: Dict[str, Any], tamper: bool = True) -> Dict[str, Any]:
        """
        Executes a controlled interception through the local proxy.
        """
        mode = "TAMPER_CIPHERTEXT" if tamper else "TRANSPARENT"
        GLOBAL_PROXY.set_mode(mode)
        result = GLOBAL_PROXY.intercept_and_forward(packet)
        return result
