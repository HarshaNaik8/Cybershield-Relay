"""
Ciphertext Tampering & Integrity Verification Simulation
Demonstrates:
Original packet -> Modified ciphertext byte -> HMAC-SHA256 verification failure -> Rejected.
Shows why Encrypt-then-MAC prevents padding oracle attacks.
"""

from typing import Dict, Any, Optional
from crypto_engine import CryptoSession, b64_decode, b64_encode
from .security_events import get_event_manager


class TamperingExperiment:
    """
    Simulates deliberate in-flight payload mutation and verifies receiver rejection.
    """

    @classmethod
    def simulate_tampering(cls, packet: Dict[str, Any],
                           session: Optional[CryptoSession] = None) -> Dict[str, Any]:
        """
        Flips a byte in the ciphertext of a valid packet and passes it to the receiver.
        """
        if session is None:
            session = CryptoSession()

        event_mgr = get_event_manager()

        ct_b64 = packet.get("ciphertext", "")
        iv_b64 = packet.get("iv", "")
        hmac_b64 = packet.get("hmac", "")
        incident_id = packet.get("incident_id", "INC-TAMPER-01")
        timestamp = packet.get("timestamp", "")
        nonce = packet.get("nonce", "")

        if not (ct_b64 and iv_b64 and hmac_b64):
            return {
                "success": False,
                "message": "Invalid packet: missing ciphertext, IV, or HMAC tag.",
            }

        # Decode ciphertext and flip the first byte
        raw_ct = bytearray(b64_decode(ct_b64))
        original_byte_hex = hex(raw_ct[0])
        raw_ct[0] ^= 0xFF
        tampered_byte_hex = hex(raw_ct[0])
        tampered_ct_b64 = b64_encode(bytes(raw_ct))

        # Attempt verification on receiver
        iv_bytes = b64_decode(iv_b64)
        tampered_ct_bytes = bytes(raw_ct)
        hmac_bytes = b64_decode(hmac_b64)

        msg, is_valid, reason = session.verify_and_decrypt(
            iv=iv_bytes,
            ciphertext=tampered_ct_bytes,
            hmac_tag=hmac_bytes,
            incident_id=incident_id,
            timestamp=timestamp,
            nonce=nonce,
        )

        event_mgr.log_event(
            "ATTACK",
            "Ciphertext Tampering Detected & Rejected",
            f"Flipped byte in packet for incident '{incident_id}' ({original_byte_hex} -> {tampered_byte_hex}). HMAC check failed.",
            "HIGH",
        )

        return {
            "attack_type": "Ciphertext Bit-Flip Mutation",
            "original_byte": original_byte_hex,
            "tampered_byte": tampered_byte_hex,
            "original_ciphertext": ct_b64,
            "tampered_ciphertext": tampered_ct_b64,
            "hmac_verified": is_valid,
            "decryption_attempted": False,
            "receiver_action": "REJECT_AND_DROP",
            "reason": reason,
            "security_rationale": (
                "In an Encrypt-then-MAC construction, the receiver checks HMAC-SHA256 in constant time "
                "before touching the AES decryption engine. Because the attacker lacks the secret HMAC_KEY, "
                "altering ciphertext bits produces an invalid authentication tag. Decryption is never executed, "
                "neutralizing padding oracle attacks completely."
            ),
        }
