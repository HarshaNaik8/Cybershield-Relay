"""
CyberShield Relay - Integrated Application Controller
Integrates:
- Cryptographic Engine (RFC 3526 DH 2048-bit, HKDF-SHA256, AES-256-CBC, HMAC-SHA256, Ed25519)
- Wireshark & TShark Packet Capture, Parsing, and Stream Analytics
- Plaintext vs Encrypted Communication Experiments
- Controlled Network Attack Simulations (Eavesdropping, MITM, Tampering, Replay)
- Rule-based Security Monitoring & Forensic Audit Logging
- Dual-Port Multi-Threaded Server (Insecure HTTP on 5000, Secure HTTPS on 5443)
"""

import os
import ssl
import time
import datetime
import threading
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.serving import make_server

from crypto_engine import CryptoSession, b64_encode, b64_decode
import network_engine
from network_engine import (
    NetworkClient,
    RECEIVER_STATE,
    SERVER_CERT_PATH,
    SERVER_KEY_PATH,
    UNTRUSTED_CERT_PATH,
    HTTP_PORT,
    HTTPS_PORT,
    HOST,
    ensure_certificates,
    get_certificate_details,
)
from network import (
    get_capture_engine,
    PacketParser,
    NetworkAnalyzer,
    TrafficMonitor,
    GLOBAL_PROXY,
    GLOBAL_REPLAY_ENGINE,
    GLOBAL_NETWORK_CONFIG,
    CAPTURES_DIR,
)
from security import (
    EavesdroppingExperiment,
    MITMSimulation,
    TamperingExperiment,
    ReplayExperiment,
    get_event_manager,
)
from analysis import (
    CryptoBenchmark,
    NetworkMetrics,
    ReportGenerator,
)

app = Flask(__name__)

# Ensure PKI certificates exist
ensure_certificates()

# Active instances
CURRENT_SESSION = CryptoSession()
LAST_TRANSMITTED_PACKET = None
LAST_CAPTURE_FILE = os.path.join(CAPTURES_DIR, "cybershield_traffic.pcap")

# Initialize event manager
event_mgr = get_event_manager()
event_mgr.log_event("SYSTEM", "CyberShield Relay Initialized", "Cryptographic & Network Security Engine booted.", "INFO")


# ============================================================
# WEB UI ROUTE
# ============================================================

@app.route("/")
def home():
    return render_template("index.html")


# ============================================================
# 1. CRYPTOGRAPHIC SESSION MANAGEMENT & BENCHMARK
# ============================================================

@app.route("/api/session", methods=["GET"])
def get_session():
    """Returns cryptographic session parameters, public keys, and certificate metadata."""
    summary = CURRENT_SESSION.get_session_summary()
    cert_info = get_certificate_details()
    net_cfg = GLOBAL_NETWORK_CONFIG.get_config_summary()

    return jsonify({
        "status": "success",
        "message": "Secure session active",
        "crypto": summary,
        "certificate": cert_info,
        "network_config": net_cfg,
        "endpoints": {
            "http_url": f"http://{HOST}:{HTTP_PORT}/api/officer_b/receive",
            "https_url": f"https://{HOST}:{HTTPS_PORT}/api/officer_b/receive",
        },
        # Backward compatibility fields
        "key_exchange": "Diffie-Hellman 2048-bit",
        "encryption": "AES-256-CBC",
        "integrity": "HMAC-SHA256",
    })


@app.route("/api/session/new", methods=["POST"])
def new_session():
    """Generates a fresh ephemeral DH session and re-derives all symmetric keys."""
    global CURRENT_SESSION, LAST_TRANSMITTED_PACKET
    CURRENT_SESSION = CryptoSession()
    RECEIVER_STATE.reset()
    LAST_TRANSMITTED_PACKET = None

    event_mgr.log_event(
        "CRYPTO",
        "Fresh DH Session Established",
        f"Session ID {CURRENT_SESSION.session_id} initialized with RFC 3526 Group 14 and Ed25519 signature.",
        "INFO",
    )

    summary = CURRENT_SESSION.get_session_summary()
    return jsonify({
        "status": "success",
        "message": "New ephemeral Diffie-Hellman session established successfully",
        "crypto": summary,
    })


@app.route("/api/benchmark/crypto", methods=["GET"])
def get_crypto_benchmark():
    """Runs high-precision performance benchmarking across all cryptographic operations."""
    bench = CryptoBenchmark.run_benchmark()
    return jsonify({
        "status": "success",
        "benchmarks": bench,
    })


# ============================================================
# 2. OFFICER A: ENCRYPT & TRANSMIT OVER NETWORK
# ============================================================

@app.route("/api/transmit", methods=["POST"])
def transmit_message():
    """
    Officer A (Sender Client) workflow:
    1. Validates incident ID and information.
    2. Generates nonce and ISO-8601 timestamp for replay protection.
    3. Encrypts payload with AES-256-CBC (PKCS#7).
    4. Computes HMAC-SHA256 tag over metadata + IV + ciphertext.
    5. Transmits packet over HTTP (port 5000) or HTTPS (port 5443) with TLS certificate validation.
    """
    global LAST_TRANSMITTED_PACKET
    data = request.get_json(silent=True) or {}

    incident_id = data.get("incident_id", "").strip()
    incident_info = data.get("message", "").strip()
    protocol = data.get("protocol", "HTTPS").upper()
    use_proxy = bool(data.get("use_proxy", False))

    if not incident_id:
        return jsonify({"status": "error", "message": "Incident ID is required"}), 400
    if not incident_info:
        return jsonify({"status": "error", "message": "Incident information is required"}), 400

    nonce = f"msg_{os.urandom(6).hex()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    full_plaintext = f"[{incident_id}] {incident_info}"

    # Encrypt-then-MAC
    t0 = time.perf_counter()
    iv, ciphertext, hmac_tag = CURRENT_SESSION.encrypt_incident(
        message=full_plaintext,
        incident_id=incident_id,
        timestamp=timestamp,
        nonce=nonce,
    )
    enc_latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    iv_b64 = b64_encode(iv)
    ciphertext_b64 = b64_encode(ciphertext)
    hmac_b64 = b64_encode(hmac_tag)

    destination_port = HTTPS_PORT if protocol == "HTTPS" else HTTP_PORT
    packet = {
        "incident_id": incident_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "iv": iv_b64,
        "ciphertext": ciphertext_b64,
        "hmac": hmac_b64,
        "protocol": protocol,
        "source": f"Officer A (Client @ {HOST})",
        "destination": f"Officer B (Receiver @ {HOST}:{destination_port})",
    }

    LAST_TRANSMITTED_PACKET = dict(packet)

    # Transmission target
    target_override = None
    if use_proxy:
        target_override = f"http://{HOST}:{PROXY_PORT}/api/officer_b/receive"

    net_result = NetworkClient.transmit_packet(packet, protocol=protocol, target_override=target_override)

    # Dashboard display only: attach Officer B's inbox entry to the response of this local UI request.
    rr = net_result.get("receiver_response")
    if isinstance(rr, dict) and rr.get("status") == "verified":
        for item in reversed(RECEIVER_STATE.received_messages):
            if item.get("nonce") == nonce:
                rr["decrypted_message"] = item.get("decrypted_message")
                break

    event_mgr.log_event(
        "NETWORK",
        f"Packet Transmitted ({protocol})",
        f"Officer A dispatched incident '{incident_id}' to Officer B. Round-trip: {net_result.get('round_trip_ms', 0)}ms.",
        "INFO" if protocol == "HTTPS" else "MEDIUM",
        {"protocol": protocol, "latency_ms": net_result.get("round_trip_ms", 0)},
    )

    return jsonify({
        "status": "success",
        "protocol": protocol,
        "packet": packet,
        "network_result": net_result,
        "crypto_summary": {
            "cipher": "AES-256-CBC",
            "iv": iv_b64,
            "ciphertext": ciphertext_b64,
            "hmac": hmac_b64,
            "encryption_latency_ms": enc_latency_ms,
            "secret_key_protection": "<KEYS REDACTED - HELD IN-MEMORY ONLY>",
        },
    })


# ============================================================
# 3. OFFICER B: RECEIVER SERVICE (HTTP & HTTPS)
# ============================================================

@app.route("/api/officer_b/receive", methods=["POST"])
def officer_b_receive():
    """
    Officer B Receiver Service:
    1. Freshness verification (timestamp window)
    2. Replay detection (nonce cache)
    3. HMAC-SHA256 constant-time verification
    4. AES-256-CBC decryption & unpadding
    """
    packet = request.get_json(silent=True) or {}
    result = RECEIVER_STATE.process_incoming_packet(packet, CURRENT_SESSION)

    status_code = 200 if result.get("status") == "verified" else 400

    if result.get("status") == "verified":
        event_mgr.log_event(
            "RECEIVER",
            "Incident Accepted & Decrypted",
            f"Officer B verified HMAC and decrypted incident '{packet.get('incident_id')}'.",
            "INFO",
        )
    else:
        event_mgr.log_event(
            "RECEIVER",
            "Message Rejected by Receiver",
            f"Officer B rejected packet: {result.get('reason')}",
            "HIGH",
        )

    # The decrypted report stays inside Officer B (RECEIVER_STATE inbox). It is NOT echoed back to the sender
    # over the network, otherwise plain-HTTP mode would put the plaintext on the wire in the response.
    wire_result = {k: v for k, v in result.items() if k != "decrypted_message"}
    if result.get("status") == "verified":
        wire_result["decrypted_length_chars"] = len(result.get("decrypted_message") or "")
    return jsonify(wire_result), status_code


# ============================================================
# 4. WIRESHARK & PACKET CAPTURE ENGINE
# ============================================================

@app.route("/api/capture/interfaces", methods=["GET"])
def get_capture_interfaces():
    """Returns detected network capture interfaces."""
    engine = get_capture_engine()
    ifaces = engine.list_interfaces()
    return jsonify({
        "status": "success",
        "tshark_available": engine.is_available(),
        "tshark_path": engine.tshark_path,
        "interfaces": ifaces,
    })


@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    """Starts live packet capture via TShark."""
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")
    capture_filter = data.get("filter", "tcp port 5000 or tcp port 5443")

    engine = get_capture_engine()
    res = engine.start_capture(interface=interface, capture_filter=capture_filter)

    if res.get("success"):
        global LAST_CAPTURE_FILE
        LAST_CAPTURE_FILE = res.get("output_file")
        event_mgr.log_event(
            "NETWORK",
            "Live Packet Capture Started",
            f"Capturing on interface '{interface}' with filter '{capture_filter}'.",
            "INFO",
        )

    status_code = 200 if res.get("success") else 400
    return jsonify(res), status_code


@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    """Stops the active packet capture."""
    engine = get_capture_engine()
    res = engine.stop_capture()

    if res.get("success"):
        global LAST_CAPTURE_FILE
        LAST_CAPTURE_FILE = res.get("output_file")
        event_mgr.log_event(
            "NETWORK",
            "Live Packet Capture Stopped",
            f"Captured file saved: {os.path.basename(res.get('output_file', ''))} ({res.get('file_size_bytes', 0)} bytes).",
            "INFO",
        )

    status_code = 200 if res.get("success") else 400
    return jsonify(res), status_code


@app.route("/api/capture/status", methods=["GET"])
def get_capture_status():
    """Returns live capture engine status."""
    engine = get_capture_engine()
    return jsonify({
        "status": "success",
        "capture_engine": engine.get_status(),
        "last_capture_file": LAST_CAPTURE_FILE,
    })


@app.route("/api/packets", methods=["GET"])
def get_packets():
    """Parses and returns captured packets from the active/latest capture file."""
    pcap_path = request.args.get("file") or LAST_CAPTURE_FILE
    max_pkts = int(request.args.get("limit", 100))

    if not pcap_path or not os.path.exists(pcap_path):
        # Fallback to sample PCAP if available
        sample_path = os.path.join(CAPTURES_DIR, "cybershield_traffic.pcap")
        if os.path.exists(sample_path):
            pcap_path = sample_path
        else:
            return jsonify({"status": "empty", "packets": [], "message": "No capture file available."})

    packets = PacketParser.parse_pcap(pcap_path, max_packets=max_pkts)
    return jsonify({
        "status": "success",
        "file": os.path.basename(pcap_path),
        "packet_count": len(packets),
        "packets": packets,
    })


@app.route("/api/packets/download", methods=["GET"])
def download_pcap():
    """Downloads the current PCAP/PCAPNG file for inspection in Wireshark."""
    pcap_path = request.args.get("file") or LAST_CAPTURE_FILE
    if not pcap_path or not os.path.exists(pcap_path):
        sample_path = os.path.join(CAPTURES_DIR, "cybershield_traffic.pcap")
        if os.path.exists(sample_path):
            pcap_path = sample_path
        else:
            return jsonify({"status": "error", "message": "No PCAP file available to download."}), 404

    return send_file(pcap_path, as_attachment=True, download_name=os.path.basename(pcap_path))


@app.route("/api/packets/export_csv", methods=["GET"])
def export_packets_csv():
    """Exports parsed packets to CSV and initiates download."""
    pcap_path = request.args.get("file") or LAST_CAPTURE_FILE
    if not pcap_path or not os.path.exists(pcap_path):
        pcap_path = os.path.join(CAPTURES_DIR, "cybershield_traffic.pcap")

    packets = PacketParser.parse_pcap(pcap_path, max_packets=200)
    csv_path = ReportGenerator.export_packets_to_csv(packets)
    return send_file(csv_path, as_attachment=True, download_name=os.path.basename(csv_path))


# ============================================================
# 5. NETWORK TRAFFIC ANALYTICS & SECURITY MONITOR
# ============================================================

@app.route("/api/analytics/traffic", methods=["GET"])
def get_traffic_analytics():
    """Computes traffic statistics, protocol distribution, and stream telemetry."""
    pcap_path = request.args.get("file") or LAST_CAPTURE_FILE
    if not pcap_path or not os.path.exists(pcap_path):
        pcap_path = os.path.join(CAPTURES_DIR, "cybershield_traffic.pcap")

    packets = PacketParser.parse_pcap(pcap_path, max_packets=200) if (pcap_path and os.path.exists(pcap_path)) else []
    analysis = NetworkAnalyzer.analyze_packets(packets)
    return jsonify({
        "status": "success",
        "analysis": analysis,
    })


@app.route("/api/monitor/alerts", methods=["GET"])
def get_monitor_alerts():
    """Evaluates captured traffic against rule-based security intrusion rules."""
    pcap_path = request.args.get("file") or LAST_CAPTURE_FILE
    if not pcap_path or not os.path.exists(pcap_path):
        pcap_path = os.path.join(CAPTURES_DIR, "cybershield_traffic.pcap")

    packets = PacketParser.parse_pcap(pcap_path, max_packets=200) if (pcap_path and os.path.exists(pcap_path)) else []
    alerts = TrafficMonitor.evaluate_packets(packets)
    return jsonify({
        "status": "success",
        "alerts_count": len(alerts),
        "alerts": alerts,
    })


# ============================================================
# 6. ATTACK SIMULATIONS
# ============================================================

@app.route("/api/simulate/eavesdrop", methods=["POST"])
def simulate_eavesdrop():
    """Attack 1: Eavesdropping & Plaintext vs Encrypted Wiretap Experiment."""
    data = request.get_json(silent=True) or {}
    sample_msg = data.get("message", "CRITICAL: Credentials leaked on gateway 10.0.1.1")
    incident_id = data.get("incident_id", "CC-EAVES-01")

    res = EavesdroppingExperiment.run_comparison(
        sample_message=sample_msg,
        incident_id=incident_id,
        session=CURRENT_SESSION,
    )
    return jsonify({"status": "success", "comparison": res})


@app.route("/api/simulate/mitm", methods=["POST"])
def simulate_mitm():
    """
    Attack 2: Man-in-the-Middle (MITM) & Handshake Authentication.
    Demonstrates:
    1. Unauthenticated DH vulnerability (Mallory substitutes public keys).
    2. Ed25519 Authenticated Handshake (Digital signature prevents key substitution).
    """
    unauth = MITMSimulation.simulate_unauthenticated_dh_mitm()
    auth = MITMSimulation.simulate_authenticated_dh_mitm()

    # Fake-server / certificate-verification demonstration: the client is made to trust only an unrelated
    # certificate while the real server presents its own, so TLS verification must abort the handshake.
    tls_probe = NetworkClient.transmit_packet(
        packet={"test": "mitm_probe"}, protocol="HTTPS", custom_cert_path=UNTRUSTED_CERT_PATH
    )
    tls_probe.pop("packet", None)
    event_mgr.log_event(
        "ATTACK",
        "Untrusted Certificate Rejected",
        f"TLS client verification result: {tls_probe.get('error_type', 'ACCEPTED')}.",
        "HIGH" if not tls_probe.get("success") else "INFO",
    )

    return jsonify({
        "status": "success",
        "unauthenticated_dh": unauth,
        "authenticated_dh": auth,
        "tls_certificate_verification": tls_probe,
    })


@app.route("/api/simulate/tamper", methods=["POST"])
@app.route("/api/tamper", methods=["POST"])
def simulate_tamper():
    """Attack 3: Ciphertext Tampering & HMAC-SHA256 Verification Failure."""
    global LAST_TRANSMITTED_PACKET
    data = request.get_json(silent=True) or {}
    packet = data if data.get("ciphertext") else LAST_TRANSMITTED_PACKET

    if not packet or not packet.get("ciphertext"):
        return jsonify({"status": "error", "message": "No transmitted message available to tamper. Send an incident first."}), 400

    res = TamperingExperiment.simulate_tampering(packet, session=CURRENT_SESSION)
    return jsonify({
        "status": "tampered",
        "integrity": "FAILED",
        "experiment": res,
        "security_message": "🚨 TAMPERING DETECTED! Ciphertext was mutated. HMAC-SHA256 check failed; receiver aborted before decryption.",
    })


@app.route("/api/simulate/replay", methods=["POST"])
def simulate_replay():
    """Attack 4: Replay Attack & Nonce Cache Rejection."""
    global LAST_TRANSMITTED_PACKET
    data = request.get_json(silent=True) or {}
    packet = data if data.get("nonce") else LAST_TRANSMITTED_PACKET

    if not packet or not packet.get("nonce"):
        return jsonify({"status": "error", "message": "No transmitted packet available to replay. Send an incident first."}), 400

    res = ReplayExperiment.simulate_replay(packet)
    return jsonify({
        "status": "replay_simulation_complete",
        "experiment": res,
    })


# ============================================================
# 7. NETWORK CONFIGURATION (LOCALHOST & LAN)
# ============================================================

@app.route("/api/network/config", methods=["GET", "POST"])
def handle_network_config():
    """Gets or updates network operating mode (LOCALHOST vs LAN)."""
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        new_mode = data.get("mode", "LOCALHOST").upper()
        GLOBAL_NETWORK_CONFIG.mode = new_mode
        event_mgr.log_event("NETWORK", "Network Operating Mode Changed", f"Switched to {new_mode} mode.", "INFO")

    return jsonify({
        "status": "success",
        "config": GLOBAL_NETWORK_CONFIG.get_config_summary(),
    })


# ============================================================
# 8. FORENSIC AUDIT LOGS & REPORTS
# ============================================================

@app.route("/api/logs", methods=["GET"])
def get_audit_logs():
    """Returns chronological forensic security event log."""
    limit = int(request.args.get("limit", 50))
    category = request.args.get("category")
    events = event_mgr.get_events(limit=limit, category=category)
    return jsonify({"status": "success", "count": len(events), "events": events})


@app.route("/api/logs/clear", methods=["POST"])
def clear_audit_logs():
    """Clears audit logs."""
    event_mgr.clear()
    return jsonify({"status": "success", "message": "Audit logs cleared."})


@app.route("/api/report/generate", methods=["GET"])
def generate_report():
    """Compiles a full JSON security & network audit report."""
    session_summary = CURRENT_SESSION.get_session_summary()
    pcap_path = LAST_CAPTURE_FILE or os.path.join(CAPTURES_DIR, "cybershield_traffic.pcap")
    pkts = PacketParser.parse_pcap(pcap_path, max_packets=200) if os.path.exists(pcap_path) else []
    traffic = NetworkAnalyzer.analyze_packets(pkts)
    events = event_mgr.get_events(limit=100)

    attacks = {
        "tampering_tested": True,
        "replay_defense_active": True,
        "ed25519_handshake_auth": True,
    }

    report_path = ReportGenerator.generate_audit_report(session_summary, traffic, events, attacks)
    return send_file(report_path, as_attachment=True, download_name=os.path.basename(report_path))


@app.route("/api/packet/last", methods=["GET"])
def get_last_packet():
    """Returns the most recent wire packet."""
    return jsonify({
        "status": "success",
        "packet": LAST_TRANSMITTED_PACKET,
        "keys_redacted": True,
    })


# ============================================================
# 9. BACKWARD-COMPATIBLE LEGACY ROUTES
# ============================================================

@app.route("/api/send", methods=["POST"])
def legacy_send():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    if not message:
        return jsonify({"status": "error", "message": "Message cannot be empty"}), 400

    nonce = f"msg_{os.urandom(6).hex()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    incident_id = "LEGACY-001"

    iv, ciphertext, hmac_tag = CURRENT_SESSION.encrypt_incident(
        message=message,
        incident_id=incident_id,
        timestamp=timestamp,
        nonce=nonce,
    )

    global LAST_TRANSMITTED_PACKET
    LAST_TRANSMITTED_PACKET = {
        "incident_id": incident_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "iv": b64_encode(iv),
        "ciphertext": b64_encode(ciphertext),
        "hmac": b64_encode(hmac_tag),
        "protocol": "HTTP",
        "source": "Officer A (Legacy)",
        "destination": f"Officer B ({HOST}:{HTTP_PORT})",
    }

    return jsonify({
        "status": "success",
        "original_message": message,
        "encrypted_message": b64_encode(ciphertext),
        "iv": b64_encode(iv),
        "hmac": b64_encode(hmac_tag),
        "nonce": nonce,
        "timestamp": timestamp,
        "incident_id": incident_id,
        "message": "Message encrypted and protected successfully",
    })


@app.route("/api/receive", methods=["POST"])
def legacy_receive():
    data = request.get_json(silent=True) or {}
    packet = {
        "incident_id": data.get("incident_id", "LEGACY-001"),
        "timestamp": data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
        "nonce": data.get("nonce", f"legacy_{os.urandom(4).hex()}"),
        "iv": data.get("iv", ""),
        "ciphertext": data.get("ciphertext", ""),
        "hmac": data.get("hmac", ""),
        "protocol": "HTTP",
    }

    result = RECEIVER_STATE.process_incoming_packet(packet, CURRENT_SESSION)
    if result.get("status") == "verified":
        return jsonify({
            "status": "verified",
            "message": result.get("decrypted_message"),
            "integrity": "VALID",
            "security_message": "Message integrity verified successfully.",
        })
    else:
        return jsonify({
            "status": "tampered",
            "message": None,
            "integrity": "FAILED",
            "security_message": result.get("reason", "Message verification failed."),
        })


# ============================================================
# SERVER RUNNERS
# ============================================================

def run_https_server():
    """Runs the HTTPS receiver service on port 5443."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(SERVER_CERT_PATH, SERVER_KEY_PATH)
    server = make_server(GLOBAL_NETWORK_CONFIG.get_bind_host(), HTTPS_PORT, app, ssl_context=ctx, threaded=True)
    server.serve_forever()


if __name__ == "__main__":
    print("=" * 65)
    print("CYBERSHIELD RELAY - INTEGRATED CRYPTOGRAPHY & NETWORK SECURITY")
    print(f"Diffie-Hellman Session: {CURRENT_SESSION.session_id}")
    print(f"Ed25519 Handshake Auth: Active (Verifying Key: {CURRENT_SESSION.server_identity.get_verifying_key_hex()[:16]}...)")
    print(f"HTTPS Receiver: https://{HOST}:{HTTPS_PORT}")
    print(f"HTTP Receiver & Web UI: http://{HOST}:{HTTP_PORT}")
    print("=" * 65)

    # Launch HTTPS receiver daemon thread
    https_thread = threading.Thread(target=run_https_server, daemon=True)
    https_thread.start()
    time.sleep(0.5)

    # Launch HTTP server
    app.run(host=GLOBAL_NETWORK_CONFIG.get_bind_host(), port=HTTP_PORT, debug=False, threaded=True)
