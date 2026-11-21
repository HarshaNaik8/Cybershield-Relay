"""
Receiver-Side Replay Protection Engine
Implements freshness verification via timestamp windows and duplicate rejection via nonce caches.
"""

import threading
import datetime
from typing import Tuple, Dict, Any, Set

MAX_CLOCK_SKEW_SECONDS = 300  # 5-minute freshness window


class ReplayProtectionEngine:
    """
    Manages nonces and timestamp verification for message freshness.
    """

    def __init__(self, max_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS):
        self.max_skew_seconds = max_skew_seconds
        self.seen_nonces: Set[str] = set()
        self.lock = threading.Lock()

    def reset(self):
        """Clears seen nonce cache."""
        with self.lock:
            self.seen_nonces.clear()

    def get_cache_size(self) -> int:
        with self.lock:
            return len(self.seen_nonces)

    def validate_packet(self, nonce: str, timestamp_str: str) -> Tuple[bool, str, str]:
        """
        Validates timestamp freshness and nonce uniqueness.
        Returns: (is_valid, error_code, reason)
        """
        if not nonce:
            return False, "MISSING_NONCE", "Packet is missing required cryptographic nonce."

        if not timestamp_str:
            return False, "MISSING_TIMESTAMP", "Packet is missing required transmission timestamp."

        # 1. Timestamp Freshness Check
        try:
            clean_ts = timestamp_str.replace("Z", "+00:00")
            msg_dt = datetime.datetime.fromisoformat(clean_ts)
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            skew = abs((now_dt - msg_dt).total_seconds())

            if skew > self.max_skew_seconds:
                return (
                    False,
                    "TIMESTAMP_EXPIRED",
                    f"Timestamp out of freshness window (skew={skew:.1f}s, max={self.max_skew_seconds}s)",
                )
        except Exception as e:
            return False, "MALFORMED_TIMESTAMP", f"Malformed ISO-8601 timestamp: {str(e)}"

        # 2. Nonce Uniqueness Check (Replay Prevention)
        with self.lock:
            if nonce in self.seen_nonces:
                return (
                    False,
                    "REPLAY_DETECTED",
                    f"🚨 REPLAY ATTACK BLOCKED: Nonce '{nonce}' has already been processed! Duplicate transmission rejected.",
                )
            self.seen_nonces.add(nonce)

        return True, "FRESH", f"Timestamp within window ({skew:.1f}s) and nonce is unique."


# Global replay protection instance
GLOBAL_REPLAY_ENGINE = ReplayProtectionEngine()
