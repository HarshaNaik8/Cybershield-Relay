"""
Replay Attack Simulation & Nonce Defense
Demonstrates:
Valid packet -> Intercepted -> Re-transmitted without alteration ->
Receiver detects duplicate nonce in seen cache -> Packet rejected.
"""

from typing import Dict, Any, Optional
from network.replay_protection import GLOBAL_REPLAY_ENGINE
from .security_events import get_event_manager


class ReplayExperiment:
    """
    Simulates capturing a valid packet and replaying it to test receiver freshness tracking.
    """

    @classmethod
    def simulate_replay(cls, packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submits the provided packet against the replay protection engine.
        If the packet was already processed, it will be rejected.
        """
        event_mgr = get_event_manager()

        nonce = packet.get("nonce", "")
        timestamp = packet.get("timestamp", "")
        incident_id = packet.get("incident_id", "INC-REPLAY-01")

        if not nonce or not timestamp:
            return {
                "success": False,
                "message": "Packet is missing nonce or timestamp required for replay evaluation.",
            }

        # Validate against global replay engine
        is_fresh, code, reason = GLOBAL_REPLAY_ENGINE.validate_packet(nonce, timestamp)

        if not is_fresh and code == "REPLAY_DETECTED":
            event_mgr.log_event(
                "ATTACK",
                "Replay Attack Blocked",
                f"Receiver detected duplicate nonce '{nonce}' for incident '{incident_id}'. Packet dropped.",
                "HIGH",
            )
            return {
                "attack_type": "Message Replay Attack",
                "attack_successful": False,
                "replay_blocked": True,
                "replayed_nonce": nonce,
                "replayed_timestamp": timestamp,
                "receiver_code": code,
                "receiver_reason": reason,
                "security_rationale": (
                    "HMAC authentication verifies that the packet was not altered, but cannot verify freshness alone. "
                    "An attacker can capture an unmodified, perfectly authentic packet and resend it. "
                    "CyberShield Relay prevents this by combining a ±300s timestamp freshness window with an in-memory "
                    "nonce cache. Replayed packets bearing previously processed nonces are detected and rejected instantly."
                ),
            }
        else:
            # First time seen
            return {
                "attack_type": "Message Replay Attack",
                "attack_successful": True,
                "replay_blocked": False,
                "replayed_nonce": nonce,
                "receiver_code": code,
                "receiver_reason": "Packet was accepted because this was its first appearance. Run again to test replay rejection.",
            }
