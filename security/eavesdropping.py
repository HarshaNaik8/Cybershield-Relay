"""
Eavesdropping & Plaintext vs. Encrypted Network Analysis Experiment
Demonstrates how packet sniffers observe cleartext data on unencrypted channels,
and how application-layer encryption + TLS protects confidentiality on the wire.
"""

import time
from typing import Dict, Any, Optional

from .security_events import get_event_manager
from crypto_engine import CryptoSession, b64_encode


class EavesdroppingExperiment:
    """
    Executes controlled comparison between plaintext and encrypted communication.
    Uses dummy lab incident messages.
    """

    @classmethod
    def run_comparison(cls, sample_message: str = "CRITICAL: Database breached on subnet 10.0.1.0/24",
                       incident_id: str = "INC-DEMO-01",
                       session: Optional[CryptoSession] = None) -> Dict[str, Any]:
        """
        Generates side-by-side telemetry comparing plaintext vs encrypted communication.
        """
        if session is None:
            session = CryptoSession()

        event_mgr = get_event_manager()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # -------------------------------------------------------------
        # EXPERIMENT A: PLAINTEXT COMMUNICATION (INTENTIONALLY INSECURE)
        # -------------------------------------------------------------
        plaintext_wire_body = f'{{"incident_id": "{incident_id}", "message": "{sample_message}", "mode": "PLAINTEXT_INSECURE"}}'
        plaintext_wire_bytes = plaintext_wire_body.encode("utf-8")
        plaintext_len = len(plaintext_wire_bytes)
        plaintext_packet_len = plaintext_len + 54  # Approx Ethernet + IP + TCP header

        # -------------------------------------------------------------
        # EXPERIMENT B: ENCRYPTED COMMUNICATION (CRYPTO ENGINE)
        # -------------------------------------------------------------
        nonce = f"msg_{int(time.time()*1000)%1000000:06x}"
        t_start = time.perf_counter()
        iv, ciphertext, hmac_tag = session.encrypt_incident(
            message=sample_message,
            incident_id=incident_id,
            timestamp=timestamp,
            nonce=nonce,
        )
        enc_time_ms = round((time.perf_counter() - t_start) * 1000, 3)

        encrypted_wire_body = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "iv": b64_encode(iv),
            "ciphertext": b64_encode(ciphertext),
            "hmac": b64_encode(hmac_tag),
            "protocol": "HTTPS (TLS 1.3)",
        }
        import json
        encrypted_wire_bytes = json.dumps(encrypted_wire_body).encode("utf-8")
        encrypted_len = len(encrypted_wire_bytes)
        encrypted_packet_len = encrypted_len + 54

        # Compute overhead
        overhead_bytes = encrypted_len - plaintext_len
        overhead_pct = round((overhead_bytes / plaintext_len) * 100, 1) if plaintext_len > 0 else 0

        event_mgr.log_event(
            "ATTACK",
            "Eavesdropping Analysis Executed",
            f"Compared plaintext vs encrypted transmission for incident '{incident_id}'. Overhead: +{overhead_bytes} bytes ({overhead_pct}%).",
            "INFO",
        )

        return {
            "incident_id": incident_id,
            "sample_message": sample_message,
            "plaintext_experiment": {
                "label": "Experiment A (Plaintext Insecure)",
                "payload_readable": True,
                "confidentiality": "NONE - Cleartext on Wire",
                "integrity_check": "NONE - Susceptible to undetected tampering",
                "wire_payload_sample": plaintext_wire_body,
                "payload_bytes": plaintext_len,
                "estimated_packet_size": plaintext_packet_len,
                "sniffer_visibility": f"Attacker reads full incident message: '{sample_message}'",
            },
            "encrypted_experiment": {
                "label": "Experiment B (AES-256 + HMAC-SHA256)",
                "payload_readable": False,
                "confidentiality": "HIGH - AES-256-CBC Encrypted",
                "integrity_check": "HIGH - HMAC-SHA256 (Encrypt-then-MAC)",
                "wire_payload_sample": f"Ciphertext: {b64_encode(ciphertext)[:32]}... | HMAC: {b64_encode(hmac_tag)[:24]}...",
                "payload_bytes": encrypted_len,
                "estimated_packet_size": encrypted_packet_len,
                "encryption_latency_ms": enc_time_ms,
                "sniffer_visibility": "Attacker observes only opaque base64 ciphertext and HMAC tag. Decryption requires 256-bit AES key.",
            },
            "comparison_metrics": {
                "overhead_bytes": overhead_bytes,
                "overhead_percentage": f"+{overhead_pct}%",
                "metadata_exposure_note": (
                    "Application encryption conceals payload content. "
                    "However, under plain HTTP, IP addresses, ports, and HTTP headers remain visible to Wireshark. "
                    "Transport encryption via TLS 1.3 is necessary to conceal transport metadata."
                ),
            },
        }
