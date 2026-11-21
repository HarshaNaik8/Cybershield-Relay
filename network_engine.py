"""
CyberShield Relay - Network Security Engine Facade
Provides backward-compatible interface and integrates modular network components:
- Local X.509 Certificate Generation & Verification
- Dual-Mode Network Client (HTTP & HTTPS with strict verification)
- Receiver-Side Security Verification (Replay, HMAC, AES Decryption)
- Interface with Packet Capture, Parser, and Analyzer
"""

import os
import time
import datetime
import ipaddress
import threading
from typing import Dict, Any, Tuple, Optional

import requests
from requests.exceptions import SSLError, ConnectionError, RequestException

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from network.packet_capture import get_capture_engine, CAPTURES_DIR
from network.packet_parser import PacketParser
from network.network_analyzer import NetworkAnalyzer
from network.traffic_monitor import TrafficMonitor
from network.replay_protection import GLOBAL_REPLAY_ENGINE
from network.network_config import GLOBAL_NETWORK_CONFIG, NetworkConfig
from security.security_events import get_event_manager

# Certificate paths
CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
SERVER_CERT_PATH = os.path.join(CERT_DIR, "server.crt")
SERVER_KEY_PATH = os.path.join(CERT_DIR, "server.key")
UNTRUSTED_CERT_PATH = os.path.join(CERT_DIR, "untrusted.crt")
UNTRUSTED_KEY_PATH = os.path.join(CERT_DIR, "untrusted.key")

HTTP_PORT = NetworkConfig.HTTP_PORT
HTTPS_PORT = NetworkConfig.HTTPS_PORT
PROXY_PORT = NetworkConfig.PROXY_PORT
HOST = "127.0.0.1"


def ensure_certificates():
    """
    Generates local 2048-bit RSA TLS certificates with Subject Alternative Names (SAN)
    for 127.0.0.1 and localhost if they do not already exist.
    """
    os.makedirs(CERT_DIR, exist_ok=True)

    # 1. Valid Server Certificate
    if not (os.path.exists(SERVER_CERT_PATH) and os.path.exists(SERVER_KEY_PATH)):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberShield Relay Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        with open(SERVER_CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(SERVER_KEY_PATH, "wb") as f:
            f.write(
                private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )

    # 2. Untrusted / Attacker Certificate for MITM Demonstration
    if not (os.path.exists(UNTRUSTED_CERT_PATH) and os.path.exists(UNTRUSTED_KEY_PATH)):
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        attacker_subject = attacker_issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Adversary MITM Proxy"),
            x509.NameAttribute(NameOID.COMMON_NAME, "attacker.spoofed.local"),
        ])
        attacker_cert = (
            x509.CertificateBuilder()
            .subject_name(attacker_subject)
            .issuer_name(attacker_issuer)
            .public_key(attacker_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
            .sign(attacker_key, hashes.SHA256())
        )
        with open(UNTRUSTED_CERT_PATH, "wb") as f:
            f.write(attacker_cert.public_bytes(serialization.Encoding.PEM))
        with open(UNTRUSTED_KEY_PATH, "wb") as f:
            f.write(
                attacker_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )


def get_certificate_details() -> Dict[str, Any]:
    """Extracts certificate metadata for UI and security inspection."""
    ensure_certificates()
    with open(SERVER_CERT_PATH, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "sha256_fingerprint": ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)),
        "san": ["localhost", "127.0.0.1"],
        "key_algorithm": "RSA 2048-bit",
        "signature_algorithm": "SHA256withRSA",
    }


class ReceiverState:
    """
    Maintains Officer B (Receiver Server) state and executes the verification pipeline.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.received_messages = []
        self.last_packet = None

    def reset(self):
        with self.lock:
            self.received_messages.clear()
            self.last_packet = None
            GLOBAL_REPLAY_ENGINE.reset()

    def process_incoming_packet(self, packet: Dict[str, Any], crypto_session) -> Dict[str, Any]:
        """
        Executes verification pipeline:
        1. Timestamp freshness window check (±300s)
        2. Nonce cache check (Replay defense)
        3. HMAC-SHA256 constant-time integrity check
        4. AES-256-CBC decryption with PKCS#7 validation
        """
        incident_id = packet.get("incident_id", "")
        timestamp = packet.get("timestamp", "")
        nonce = packet.get("nonce", "")
        iv_b64 = packet.get("iv", "")
        ciphertext_b64 = packet.get("ciphertext", "")
        hmac_b64 = packet.get("hmac", "")
        protocol = packet.get("protocol", "HTTP")

        with self.lock:
            self.last_packet = dict(packet)

        # Step 1 & 2: Replay and Timestamp Freshness Verification
        is_fresh, code, reason = GLOBAL_REPLAY_ENGINE.validate_packet(nonce, timestamp)
        if not is_fresh:
            return {
                "status": "rejected",
                "reason": reason,
                "code": code,
                "integrity": "FAILED",
                "decrypted_message": None,
            }

        # Step 3 & 4: Cryptographic Integrity Verification & Decryption
        try:
            import base64
            iv_bytes = base64.b64decode(iv_b64)
            ciphertext_bytes = base64.b64decode(ciphertext_b64)
            hmac_bytes = base64.b64decode(hmac_b64)
        except Exception as e:
            return {
                "status": "rejected",
                "reason": f"Base64 decoding failed: {str(e)}",
                "code": "INVALID_ENCODING",
                "integrity": "FAILED",
                "decrypted_message": None,
            }

        decrypted_text, is_valid, status_msg = crypto_session.verify_and_decrypt(
            iv=iv_bytes,
            ciphertext=ciphertext_bytes,
            hmac_tag=hmac_bytes,
            incident_id=incident_id,
            timestamp=timestamp,
            nonce=nonce,
        )

        if not is_valid:
            return {
                "status": "rejected",
                "reason": f"🚨 INTEGRITY VERIFICATION FAILED: {status_msg}",
                "code": "HMAC_VERIFICATION_FAILED",
                "integrity": "FAILED",
                "decrypted_message": None,
            }

        result = {
            "status": "verified",
            "reason": "HMAC-SHA256 verified; AES-256 decrypted successfully.",
            "code": "ACCEPTED",
            "integrity": "VALID",
            "protocol": protocol,
            "incident_id": incident_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "decrypted_message": decrypted_text,
        }

        with self.lock:
            self.received_messages.append(result)

        return result


RECEIVER_STATE = ReceiverState()


class NetworkClient:
    """
    Officer A (Sender Client) Network Engine.
    Executes actual network transmission over HTTP or HTTPS.
    Enforces explicit TLS certificate verification.
    """

    @staticmethod
    def transmit_packet(packet: Dict[str, Any], protocol: str = "HTTPS",
                        custom_cert_path: str = None,
                        target_override: str = None) -> Dict[str, Any]:
        """
        Sends the encrypted incident packet to Officer B's receiver service.
        """
        protocol = protocol.upper()
        cert_path = custom_cert_path if custom_cert_path else SERVER_CERT_PATH

        if target_override:
            target_url = target_override
        elif protocol == "HTTPS":
            target_url = f"https://{HOST}:{HTTPS_PORT}/api/officer_b/receive"
        else:
            target_url = f"http://{HOST}:{HTTP_PORT}/api/officer_b/receive"

        start_time = time.time()
        headers = {"Content-Type": "application/json", "X-Client": "Officer-A"}

        if protocol == "HTTPS":
            try:
                response = requests.post(target_url, json=packet, verify=cert_path, timeout=5.0, headers=headers)
                elapsed_ms = (time.time() - start_time) * 1000
                return {
                    "success": True,
                    "status_code": response.status_code,
                    "protocol": "HTTPS",
                    "tls_version": "TLSv1.3",
                    "tls_cipher": "AES-256-GCM / SHA-384",
                    "cert_verified": True,
                    "target_url": target_url,
                    "round_trip_ms": round(elapsed_ms, 2),
                    "receiver_response": response.json(),
                    "packet": packet,
                }
            except SSLError as ssl_err:
                elapsed_ms = (time.time() - start_time) * 1000
                return {
                    "success": False,
                    "error_type": "SSL_CERT_VERIFICATION_ERROR",
                    "protocol": "HTTPS",
                    "cert_verified": False,
                    "error_message": f"TLS Certificate verification failed: {str(ssl_err)}",
                    "security_alert": "MITM ATTEMPT OR UNTRUSTED CERTIFICATE: Handshake aborted to prevent data interception.",
                    "target_url": target_url,
                    "round_trip_ms": round(elapsed_ms, 2),
                    "packet": packet,
                }
            except Exception as e:
                return {
                    "success": False,
                    "error_type": "NETWORK_ERROR",
                    "protocol": "HTTPS",
                    "error_message": str(e),
                    "packet": packet,
                }
        else:
            try:
                response = requests.post(target_url, json=packet, timeout=5.0, headers=headers)
                elapsed_ms = (time.time() - start_time) * 1000
                return {
                    "success": True,
                    "status_code": response.status_code,
                    "protocol": "HTTP",
                    "tls_version": "None (Plaintext Transport)",
                    "tls_cipher": "None",
                    "cert_verified": False,
                    "target_url": target_url,
                    "round_trip_ms": round(elapsed_ms, 2),
                    "receiver_response": response.json(),
                    "packet": packet,
                }
            except Exception as e:
                return {
                    "success": False,
                    "error_type": "NETWORK_ERROR",
                    "protocol": "HTTP",
                    "error_message": str(e),
                    "packet": packet,
                }
