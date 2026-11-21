"""
Network Traffic & Protocol Analyzer
Computes traffic statistics, protocol distributions, packet size distributions,
TCP stream reconstructions, and network throughput from parsed packets.
"""

from typing import List, Dict, Any
from collections import defaultdict


class NetworkAnalyzer:
    """
    Analyzes packet collections to produce comprehensive traffic telemetry.
    """

    @classmethod
    def analyze_packets(cls, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Executes full statistical and protocol analysis across parsed packets.
        """
        if not packets:
            return cls._empty_analysis()

        total_packets = len(packets)
        total_bytes = sum(p.get("length", 0) for p in packets)

        # 1. Protocol Distribution
        protocol_counts: Dict[str, int] = defaultdict(int)
        for p in packets:
            proto = p.get("protocol") or "TCP"
            protocol_counts[proto] += 1

        # 2. Packet Size Distribution
        lengths = [p.get("length", 0) for p in packets]
        min_size = min(lengths) if lengths else 0
        max_size = max(lengths) if lengths else 0
        avg_size = round(total_bytes / total_packets, 2) if total_packets > 0 else 0

        size_buckets = {
            "small (<100B)": sum(1 for l in lengths if l < 100),
            "medium (100-500B)": sum(1 for l in lengths if 100 <= l < 500),
            "large (500-1500B)": sum(1 for l in lengths if 500 <= l < 1500),
            "jumbo (>1500B)": sum(1 for l in lengths if l >= 1500),
        }

        # 3. TCP Stream Analysis
        streams_dict: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for p in packets:
            sid = p.get("stream_id", 0)
            streams_dict[sid].append(p)

        analyzed_streams = []
        for sid, stream_pkts in streams_dict.items():
            first_pkt = stream_pkts[0]
            client_ep = f"{first_pkt.get('src_ip')}:{first_pkt.get('src_port')}"
            server_ep = f"{first_pkt.get('dst_ip')}:{first_pkt.get('dst_port')}"
            # A capture may begin mid-stream: the endpoint on a service port (5000/5443) is always the server.
            if first_pkt.get("src_port") in (5000, 5443) and first_pkt.get("dst_port") not in (5000, 5443):
                client_ep, server_ep = server_ep, client_ep

            c2s = sum(1 for p in stream_pkts if f"{p.get('src_ip')}:{p.get('src_port')}" == client_ep)
            s2c = len(stream_pkts) - c2s
            stream_bytes = sum(p.get("length", 0) for p in stream_pkts)

            # Determine dominant protocol in stream
            stream_proto = "TCP"
            for p in stream_pkts:
                if "HTTP" in p.get("protocol", ""):
                    stream_proto = "HTTP"
                    break
                elif "TLS" in p.get("protocol", ""):
                    stream_proto = "TLS"
                    break

            analyzed_streams.append({
                "stream_id": sid,
                "client_endpoint": client_ep,
                "server_endpoint": server_ep,
                "packet_count": len(stream_pkts),
                "client_to_server": c2s,
                "server_to_client": s2c,
                "total_bytes": stream_bytes,
                "protocol": stream_proto,
            })

        # 4. Endpoints Statistics
        src_ips: Dict[str, int] = defaultdict(int)
        dst_ports: Dict[int, int] = defaultdict(int)
        for p in packets:
            src_ips[p.get("src_ip", "127.0.0.1")] += 1
            if p.get("dst_port"):
                dst_ports[p.get("dst_port")] += 1

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "min_packet_size": min_size,
            "max_packet_size": max_size,
            "avg_packet_size": avg_size,
            "protocol_distribution": dict(protocol_counts),
            "size_buckets": size_buckets,
            "tcp_streams": analyzed_streams,
            "active_streams_count": len(analyzed_streams),
            "source_ip_stats": dict(src_ips),
            "destination_port_stats": dict(dst_ports),
        }

    @staticmethod
    def _empty_analysis() -> Dict[str, Any]:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "min_packet_size": 0,
            "max_packet_size": 0,
            "avg_packet_size": 0,
            "protocol_distribution": {},
            "size_buckets": {},
            "tcp_streams": [],
            "active_streams_count": 0,
            "source_ip_stats": {},
            "destination_port_stats": {},
        }
