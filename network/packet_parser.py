"""
Deep Packet Parser and Hex/ASCII Inspector
Extracts detailed OSI Layer 2-7 packet metadata, protocol fields,
TCP flags, stream indices, and formats hexadecimal/ASCII dumps.
"""

import os
import json
import struct
import subprocess
from typing import List, Dict, Any, Optional

from .packet_capture import get_capture_engine


class PacketParser:
    """
    Parses PCAP/PCAPNG files to extract packet summaries,
    protocol layers, and raw payload dumps.
    """

    @staticmethod
    def format_hex_ascii_dump(data_bytes: bytes, bytes_per_line: int = 16) -> Dict[str, str]:
        """
        Formats raw payload bytes into classic Wireshark hex and ASCII representations.
        """
        hex_lines = []
        ascii_lines = []
        combined_lines = []

        for i in range(0, len(data_bytes), bytes_per_line):
            chunk = data_bytes[i:i + bytes_per_line]
            offset = f"{i:04x}"

            # Hex string (e.g., "45 00 00 3c ...")
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            hex_part_padded = hex_part.ljust(bytes_per_line * 3 - 1)

            # ASCII string with non-printables as dots
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)

            hex_lines.append(f"{offset}  {hex_part}")
            ascii_lines.append(ascii_part)
            combined_lines.append(f"{offset}  {hex_part_padded}  |{ascii_part}|")

        return {
            "hex_dump": "\n".join(hex_lines),
            "ascii_dump": "\n".join(ascii_lines),
            "combined_dump": "\n".join(combined_lines),
        }

    @classmethod
    def parse_pcap(cls, pcap_path: str, max_packets: int = 100) -> List[Dict[str, Any]]:
        """
        Parses a PCAP/PCAPNG file using TShark or fallback parser.
        """
        if not os.path.exists(pcap_path):
            return []

        engine = get_capture_engine()
        if engine.is_available():
            return cls._parse_with_tshark(engine.tshark_path, pcap_path, max_packets)
        else:
            return cls._parse_fallback_pcap(pcap_path, max_packets)

    @classmethod
    def _parse_with_tshark(cls, tshark_path: str, pcap_path: str,
                           max_packets: int = 100) -> List[Dict[str, Any]]:
        """Invokes TShark in JSON export mode to extract protocol tree."""
        packets = []
        cmd = [
            tshark_path,
            "-r", pcap_path,
            "-T", "json",
            "-c", str(max_packets),
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15.0)
            if res.returncode == 0 and res.stdout:
                json_data = json.loads(res.stdout)
                for idx, pkt in enumerate(json_data, 1):
                    parsed = cls._normalize_tshark_packet(idx, pkt)
                    if parsed:
                        packets.append(parsed)
        except Exception as e:
            # Fallback to text parsing if JSON parsing fails
            return cls._parse_with_tshark_fields(tshark_path, pcap_path, max_packets)

        return packets

    @classmethod
    def _parse_with_tshark_fields(cls, tshark_path: str, pcap_path: str,
                                 max_packets: int = 100) -> List[Dict[str, Any]]:
        """Fast tabular field extraction using TShark -T fields."""
        packets = []
        cmd = [
            tshark_path,
            "-r", pcap_path,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "tcp.flags.str",
            "-e", "tcp.seq",
            "-e", "tcp.ack",
            "-e", "tcp.len",
            "-e", "tcp.stream",
            "-e", "http.request.method",
            "-e", "http.request.uri",
            "-e", "data.data",
            "-c", str(max_packets),
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10.0)
            if res.returncode == 0:
                for line in res.stdout.strip().splitlines():
                    fields = line.split("\t")
                    num = fields[0] if len(fields) > 0 and fields[0] else str(len(packets) + 1)
                    time_epoch = float(fields[1]) if len(fields) > 1 and fields[1] else 0.0
                    src_ip = fields[2] if len(fields) > 2 and fields[2] else "127.0.0.1"
                    dst_ip = fields[3] if len(fields) > 3 and fields[3] else "127.0.0.1"
                    src_port = int(fields[4]) if len(fields) > 4 and fields[4] else 0
                    dst_port = int(fields[5]) if len(fields) > 5 and fields[5] else 0
                    proto = fields[6] if len(fields) > 6 and fields[6] else "TCP"
                    pkt_len = int(fields[7]) if len(fields) > 7 and fields[7] else 0
                    flags = fields[8] if len(fields) > 8 and fields[8] else ""
                    seq = fields[9] if len(fields) > 9 and fields[9] else "0"
                    ack = fields[10] if len(fields) > 10 and fields[10] else "0"
                    tcp_len = int(fields[11]) if len(fields) > 11 and fields[11] else 0
                    stream_id = int(fields[12]) if len(fields) > 12 and fields[12] else 0
                    http_m = fields[13] if len(fields) > 13 and fields[13] else None
                    http_u = fields[14] if len(fields) > 14 and fields[14] else None
                    raw_data_hex = fields[15] if len(fields) > 15 and fields[15] else ""

                    data_bytes = bytes.fromhex(raw_data_hex.replace(":", "")) if raw_data_hex else b""
                    dumps = cls.format_hex_ascii_dump(data_bytes)

                    packets.append({
                        "packet_number": int(num),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time_epoch)) if time_epoch else "N/A",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": proto,
                        "length": pkt_len,
                        "tcp_flags": flags,
                        "seq_number": seq,
                        "ack_number": ack,
                        "payload_length": tcp_len,
                        "stream_id": stream_id,
                        "http_method": http_m,
                        "http_uri": http_u,
                        "payload_preview": dumps["ascii_dump"][:120] if dumps["ascii_dump"] else (
                            "[TLS Encrypted Application Data]" if "TLS" in proto else "[No Payload / Handshake]"
                        ),
                        "hex_dump": dumps["hex_dump"],
                        "ascii_dump": dumps["ascii_dump"],
                        "combined_dump": dumps["combined_dump"],
                    })
        except Exception:
            pass

        return packets

    @staticmethod
    def decode_tcp_flags(flags_hex) -> str:
        """Converts the TCP flags field (e.g. '0x0018') into names such as 'ACK, PSH'."""
        try:
            value = int(str(flags_hex), 16)
        except ValueError:
            return ""
        names = [(0x100, "NS"), (0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"), (0x10, "ACK"),
                 (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN")]
        return ", ".join(name for bit, name in names if value & bit)

    @classmethod
    def _normalize_tshark_packet(cls, idx: int, pkt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extracts and normalizes packet fields from TShark JSON tree."""
        layers = pkt.get("_source", {}).get("layers", {})
        if not layers:
            return None

        frame = layers.get("frame", {})
        ip = layers.get("ip", {}) or layers.get("ipv6", {})
        tcp = layers.get("tcp", {})
        http = layers.get("http", {})
        tls = layers.get("tls", {}) or layers.get("ssl", {})

        src_ip = ip.get("ip.src", "127.0.0.1")
        dst_ip = ip.get("ip.dst", "127.0.0.1")
        src_port = int(tcp.get("tcp.srcport", 0))
        dst_port = int(tcp.get("tcp.dstport", 0))

        # Protocol determination
        proto = "TCP"
        if http:
            proto = "HTTP"
        elif tls:
            proto = "TLSv1.3" if "tls.record.version" in str(tls) else "TLS"
        elif "udp" in layers:
            proto = "UDP"

        pkt_len = int(frame.get("frame.len", 0))
        tcp_len = int(tcp.get("tcp.len", 0))
        stream_id = int(tcp.get("tcp.stream", 0))

        # Extract payload data bytes
        data_layer = layers.get("data", {})
        # HTTP/TLS packets are decoded into their own layers, so fall back to the raw TCP payload
        raw_hex = data_layer.get("data.data", "") or tcp.get("tcp.payload", "")
        data_bytes = bytes.fromhex(raw_hex.replace(":", "")) if raw_hex else b""
        dumps = cls.format_hex_ascii_dump(data_bytes)

        return {
            "packet_number": idx,
            "timestamp": frame.get("frame.time", "N/A"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "length": pkt_len,
            "tcp_flags": cls.decode_tcp_flags(tcp.get("tcp.flags", "0x0")),
            "seq_number": tcp.get("tcp.seq", "0"),
            "ack_number": tcp.get("tcp.ack", "0"),
            "payload_length": tcp_len,
            "stream_id": stream_id,
            "http_method": http.get("http.request.method"),
            "http_uri": http.get("http.request.uri"),
            "payload_preview": dumps["ascii_dump"][:120] if dumps["ascii_dump"] else (
                "[TLS Encrypted Application Data]" if "TLS" in proto else "[No Payload / Handshake]"
            ),
            "hex_dump": dumps["hex_dump"],
            "ascii_dump": dumps["ascii_dump"],
            "combined_dump": dumps["combined_dump"],
        }

    @classmethod
    def _parse_fallback_pcap(cls, pcap_path: str, max_packets: int = 100) -> List[Dict[str, Any]]:
        """
        Pure Python standard PCAP parser fallback.
        Reads classic libpcap 24-byte header and packet headers.
        """
        packets = []
        try:
            with open(pcap_path, "rb") as f:
                header = f.read(24)
                if len(header) < 24:
                    return []
                magic = struct.unpack("!I", header[:4])[0]
                is_be = (magic == 0xa1b2c3d4)

                fmt_pkt_hdr = "!IIII" if is_be else "<IIII"

                idx = 1
                while idx <= max_packets:
                    pkt_hdr = f.read(16)
                    if len(pkt_hdr) < 16:
                        break
                    ts_sec, ts_usec, caplen, origlen = struct.unpack(fmt_pkt_hdr, pkt_hdr)
                    raw_data = f.read(caplen)

                    dumps = cls.format_hex_ascii_dump(raw_data[:256])

                    packets.append({
                        "packet_number": idx,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts_sec)),
                        "src_ip": "127.0.0.1",
                        "dst_ip": "127.0.0.1",
                        "src_port": 5000,
                        "dst_port": 5000,
                        "protocol": "TCP/RAW",
                        "length": origlen,
                        "tcp_flags": "[ACK]",
                        "seq_number": "1",
                        "ack_number": "1",
                        "payload_length": caplen,
                        "stream_id": 0,
                        "http_method": None,
                        "http_uri": None,
                        "payload_preview": dumps["ascii_dump"][:120],
                        "hex_dump": dumps["hex_dump"],
                        "ascii_dump": dumps["ascii_dump"],
                        "combined_dump": dumps["combined_dump"],
                    })
                    idx += 1
        except Exception:
            pass

        return packets
