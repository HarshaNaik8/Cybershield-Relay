"""
CyberShield Relay - Security Attack Simulation & Audit Package
Provides:
- Eavesdropping & Plaintext vs Encrypted Experiment
- MITM Interception & Ed25519 Authenticated Handshake Defense
- Ciphertext Tampering & HMAC-SHA256 Defense
- Replay Attack Simulation & Nonce Defense
- Central Forensic Security Audit Trail
"""

from .eavesdropping import EavesdroppingExperiment
from .mitm_simulation import MITMSimulation
from .tampering import TamperingExperiment
from .replay_attack import ReplayExperiment
from .security_events import SecurityEventManager, get_event_manager

__all__ = [
    "EavesdroppingExperiment",
    "MITMSimulation",
    "TamperingExperiment",
    "ReplayExperiment",
    "SecurityEventManager",
    "get_event_manager",
]
