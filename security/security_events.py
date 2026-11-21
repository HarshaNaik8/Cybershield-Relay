"""
Central Forensic Security Audit Event Logger
Maintains a thread-safe, structured audit trail of all cryptographic,
network, and attack events with timestamps, severity levels, and category tags.
Never stores private keys, AES keys, passwords, or raw session secrets.
"""

import time
import threading
from typing import List, Dict, Any, Optional

MAX_STORED_EVENTS = 500


class SecurityEventManager:
    """
    Thread-safe event auditor.
    """

    def __init__(self, max_events: int = MAX_STORED_EVENTS):
        self.max_events = max_events
        self.events: List[Dict[str, Any]] = []
        self.lock = threading.Lock()

    def log_event(self, category: str, title: str, description: str,
                  severity: str = "INFO", metadata: Optional[Dict[str, Any]] = None):
        """
        Records a new audit event.
        Category: 'CRYPTO', 'NETWORK', 'ATTACK', 'RECEIVER', 'SYSTEM'
        Severity: 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        """
        now = time.time()
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

        event = {
            "id": f"EVT-{int(now * 1000) % 1000000:06d}",
            "timestamp": timestamp_str,
            "epoch": now,
            "category": category.upper(),
            "severity": severity.upper(),
            "title": title,
            "description": description,
            "metadata": metadata or {},
        }

        with self.lock:
            self.events.insert(0, event)  # newest first
            if len(self.events) > self.max_events:
                self.events.pop()

        return event

    def get_events(self, limit: int = 50, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns recorded events, optionally filtered by category."""
        with self.lock:
            if category:
                cat_upper = category.upper()
                filtered = [e for e in self.events if e.get("category") == cat_upper]
                return filtered[:limit]
            return list(self.events[:limit])

    def clear(self):
        """Clears all audit events."""
        with self.lock:
            self.events.clear()


# Global event manager instance
_GLOBAL_EVENT_MANAGER = SecurityEventManager()

def get_event_manager() -> SecurityEventManager:
    return _GLOBAL_EVENT_MANAGER
