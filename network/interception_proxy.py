"""
Controlled Application-Layer Interception Proxy
Demonstrates Man-in-the-Middle (MITM) inspection, payload modification,
and forwarding in a safe localhost testbed.
Architecture:
Officer A (Sender) -> Interception Proxy (Port 5080) -> Officer B (Port 5000/5443)
"""

import threading
import requests
from typing import Dict, Any, Optional

PROXY_PORT = 5080
TARGET_HOST = "127.0.0.1"


class InterceptionProxy:
    """
    Simulates an in-line network proxy that can inspect, forward, or tamper with messages.
    """

    def __init__(self, target_port: int = 5000):
        self.target_port = target_port
        self.mode = "TRANSPARENT"  # "TRANSPARENT", "TAMPER_CIPHERTEXT", "TAMPER_METADATA"
        self.intercepted_history = []
        self.lock = threading.Lock()

    def set_mode(self, mode: str):
        """Sets proxy operation mode."""
        with self.lock:
            self.mode = mode

    def intercept_and_forward(self, packet: Dict[str, Any],
                              target_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Intercepts incoming client packet, applies proxy manipulation based on active mode,
        forwards to destination receiver, and logs the transaction.
        """
        if not target_url:
            target_url = f"http://{TARGET_HOST}:{self.target_port}/api/officer_b/receive"

        with self.lock:
            mode = self.mode

        forwarded_packet = dict(packet)
        action_taken = "FORWARD_UNMODIFIED"

        # Apply MITM Manipulation
        if mode == "TAMPER_CIPHERTEXT":
            ct = forwarded_packet.get("ciphertext", "")
            if ct:
                # Mutate base64 ciphertext
                import base64
                try:
                    raw = bytearray(base64.b64decode(ct))
                    raw[0] ^= 0xFF
                    forwarded_packet["ciphertext"] = base64.b64encode(bytes(raw)).decode("utf-8")
                    action_taken = "MODIFIED_CIPHERTEXT_BYTE"
                except Exception:
                    pass

        elif mode == "TAMPER_METADATA":
            forwarded_packet["incident_id"] = "SPOOFED-" + str(forwarded_packet.get("incident_id", ""))
            action_taken = "SPOOFED_INCIDENT_ID"

        # Forward to actual receiver
        try:
            resp = requests.post(target_url, json=forwarded_packet, timeout=5.0)
            receiver_json = resp.json()
            receiver_status_code = resp.status_code
        except Exception as e:
            receiver_json = {"status": "error", "message": f"Proxy forward failed: {str(e)}"}
            receiver_status_code = 502

        record = {
            "mode": mode,
            "action": action_taken,
            "original_packet": packet,
            "forwarded_packet": forwarded_packet,
            "target_url": target_url,
            "receiver_status_code": receiver_status_code,
            "receiver_response": receiver_json,
        }

        with self.lock:
            self.intercepted_history.append(record)

        return record

    def get_history(self):
        with self.lock:
            return list(self.intercepted_history)

    def clear_history(self):
        with self.lock:
            self.intercepted_history.clear()


# Global proxy instance
GLOBAL_PROXY = InterceptionProxy()
