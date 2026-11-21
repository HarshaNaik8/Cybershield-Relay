"""
Network Performance & Transmission Telemetry
Measures round-trip latencies, network throughput, and packet-to-payload ratios.
"""

from typing import Dict, Any, List


class NetworkMetrics:
    """
    Computes bandwidth, throughput, and overhead ratios from transmission measurements.
    """

    @staticmethod
    def calculate_throughput(total_bytes: int, duration_seconds: float) -> Dict[str, Any]:
        """Calculates network throughput in bytes/s and KB/s."""
        if duration_seconds <= 0:
            duration_seconds = 0.001

        bytes_per_sec = total_bytes / duration_seconds
        kb_per_sec = bytes_per_sec / 1024.0

        return {
            "total_bytes": total_bytes,
            "duration_seconds": round(duration_seconds, 3),
            "bytes_per_sec": round(bytes_per_sec, 2),
            "kb_per_sec": round(kb_per_sec, 2),
        }

    @staticmethod
    def calculate_overhead(plaintext_bytes: int, packet_bytes: int) -> Dict[str, Any]:
        """Calculates overhead added by cryptography and transport headers."""
        if plaintext_bytes <= 0:
            return {"overhead_bytes": 0, "overhead_ratio": 1.0}

        overhead = packet_bytes - plaintext_bytes
        ratio = packet_bytes / plaintext_bytes

        return {
            "plaintext_bytes": plaintext_bytes,
            "packet_bytes": packet_bytes,
            "overhead_bytes": overhead,
            "overhead_ratio": round(ratio, 2),
            "overhead_percentage": round((overhead / plaintext_bytes) * 100, 1),
        }
