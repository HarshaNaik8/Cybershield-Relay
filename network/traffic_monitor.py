"""
Rule-Based Network Security Traffic Monitor
Evaluates captured packets against transparent security detection rules
to detect plaintext leakage, port anomalies, retransmission bursts, and suspicious behavior.
"""

from typing import List, Dict, Any
import time


class TrafficMonitor:
    """
    Transparent, rule-based security event detector.
    Does not falsely advertise machine learning; executes documented deterministic rules.
    """

    ALLOWED_PORTS = {5000, 5443, 5080, 80, 443}

    @classmethod
    def evaluate_packets(cls, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scans a list of parsed packets and applies security inspection rules.
        """
        alerts = []
        if not packets:
            return alerts

        retransmission_count = 0
        http_requests = 0

        for p in packets:
            pkt_num = p.get("packet_number", 0)
            dst_port = p.get("dst_port", 0)
            src_port = p.get("src_port", 0)
            proto = p.get("protocol", "")
            flags = p.get("tcp_flags", "")
            payload_preview = p.get("payload_preview", "")
            timestamp = p.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))

            # Rule 1: Plaintext transmission of incident data over unencrypted HTTP
            if proto == "HTTP" and dst_port == 5000:
                http_requests += 1
                if "incident" in payload_preview.lower() or "CC-" in payload_preview:
                    alerts.append({
                        "id": f"ALT-{pkt_num}-1",
                        "severity": "HIGH",
                        "rule": "RULE_PLAINTEXT_SENSITIVE_LEAK",
                        "description": f"Packet #{pkt_num} transmitted sensitive incident keywords over cleartext HTTP (Port 5000).",
                        "packet_number": pkt_num,
                        "timestamp": timestamp,
                        "remediation": "Upgrade transmission channel to HTTPS over TLS (Port 5443) with strict certificate validation.",
                    })

            # Rule 2: Non-standard application port. Server replies (source port 5000/5443) go to the client's
            # ephemeral port and are normal, so only flag packets where neither endpoint is an allowed port.
            if dst_port > 0 and dst_port not in cls.ALLOWED_PORTS and src_port not in cls.ALLOWED_PORTS:
                alerts.append({
                    "id": f"ALT-{pkt_num}-2",
                    "severity": "MEDIUM",
                    "rule": "RULE_UNEXPECTED_PORT",
                    "description": f"Packet #{pkt_num} directed to unexpected destination port {dst_port}.",
                    "packet_number": pkt_num,
                    "timestamp": timestamp,
                    "remediation": "Verify network routing table and restrict firewall ingress rules to authorized ports 5000/5443.",
                })

            # Rule 3: TCP Flag anomalies (e.g. SYN-FIN or anomalous combinations)
            if "SYN" in flags and "FIN" in flags:
                alerts.append({
                    "id": f"ALT-{pkt_num}-3",
                    "severity": "CRITICAL",
                    "rule": "RULE_SUSPICIOUS_TCP_FLAGS",
                    "description": f"Packet #{pkt_num} exhibits invalid TCP flag combination [SYN, FIN] (potential port scan or probe).",
                    "packet_number": pkt_num,
                    "timestamp": timestamp,
                    "remediation": "Drop anomalous flag packets at OS kernel firewall via TCP stateful tracking.",
                })

            # Rule 4: Retransmission tracking
            if "retransmission" in str(p).lower():
                retransmission_count += 1

        # Rule 5: Retransmission burst alert
        if retransmission_count > 5:
            alerts.append({
                "id": "ALT-NET-RETRANS",
                "severity": "LOW",
                "rule": "RULE_RETRANSMISSION_BURST",
                "description": f"Detected {retransmission_count} TCP retransmissions indicating packet loss, congestion, or active interference.",
                "packet_number": 0,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "remediation": "Inspect network interface statistics and verify MTU configuration.",
            })

        return alerts
