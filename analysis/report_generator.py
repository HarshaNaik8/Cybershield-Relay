"""
Forensic Report & CSV Export Generator
Exports captured packet streams to CSV format and compiles structured
cryptographic and network audit reports.
"""

import os
import csv
import json
import time
from typing import List, Dict, Any

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")


class ReportGenerator:
    """
    Compiles forensic reports and CSV data files.
    """

    @classmethod
    def export_packets_to_csv(cls, packets: List[Dict[str, Any]], filename: str = None) -> str:
        """
        Exports a list of parsed packets into a standard CSV file.
        Returns the absolute path to the generated CSV.
        """
        os.makedirs(REPORTS_DIR, exist_ok=True)
        if not filename:
            filename = f"packets_{time.strftime('%Y%m%d_%H%M%S')}.csv"

        filepath = os.path.join(REPORTS_DIR, filename)

        fieldnames = [
            "packet_number", "timestamp", "src_ip", "src_port",
            "dst_ip", "dst_port", "protocol", "length",
            "tcp_flags", "stream_id", "http_method", "http_uri", "payload_preview"
        ]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for p in packets:
                clean_p = dict(p)
                clean_p["payload_preview"] = (p.get("payload_preview") or "").replace("\n", " ").replace("\r", "")[:100]
                writer.writerow(clean_p)

        return filepath

    @classmethod
    def generate_audit_report(cls, session_summary: Dict[str, Any],
                              traffic_analysis: Dict[str, Any],
                              events: List[Dict[str, Any]],
                              attacks_summary: Dict[str, Any]) -> str:
        """
        Compiles a comprehensive JSON forensic audit report and saves it to reports/.
        Returns the absolute path to the report.
        """
        os.makedirs(REPORTS_DIR, exist_ok=True)
        filename = f"audit_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(REPORTS_DIR, filename)

        report = {
            "title": "CyberShield Relay - Forensic Security & Network Telemetry Report",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "cryptographic_session": session_summary,
            "network_telemetry": traffic_analysis,
            "attack_simulations": attacks_summary,
            "forensic_events": events,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return filepath
