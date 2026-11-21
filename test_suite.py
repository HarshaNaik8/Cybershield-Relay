"""
CyberShield Relay - Automated Security Test Suite
Covers:
TEST 1: Normal HTTP Transmission
TEST 2: Secure HTTPS Transmission (with TLS Certificate Verification)
TEST 3: Ciphertext Tampering Detection (HMAC failure)
TEST 4: Replay Attack Prevention (Nonce & Timestamp validation)
TEST 5: Invalid TLS Certificate (Untrusted cert rejection / MITM detection)
TEST 6: Invalid or Missing Authentication Tag
TEST 7: Normal End-to-End Decryption Accuracy
TEST 8: Legacy endpoint compatibility
"""

import os
import sys
import time
import ssl
import threading
import requests
from werkzeug.serving import make_server

# Import project modules
from app import app, run_https_server
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
)


def start_test_servers():
    """
    Starts both HTTP and HTTPS servers in background threads for testing.
    """
    ensure_certificates()

    # HTTPS Server Thread (threaded=True to avoid deadlock on nested calls)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(SERVER_CERT_PATH, SERVER_KEY_PATH)
    https_server = make_server(HOST, HTTPS_PORT, app, ssl_context=ctx, threaded=True)
    t_https = threading.Thread(target=https_server.serve_forever, daemon=True)
    t_https.start()

    # HTTP Server Thread (threaded=True to avoid deadlock on nested calls)
    http_server = make_server(HOST, HTTP_PORT, app, threaded=True)
    t_http = threading.Thread(target=http_server.serve_forever, daemon=True)
    t_http.start()

    time.sleep(1.0)
    return https_server, http_server


def run_tests():
    print("=" * 70)
    print("CYBERSHIELD RELAY - EXECUTING VERIFICATION TEST SUITE")
    print("=" * 70)

    https_srv, http_srv = start_test_servers()
    all_passed = True
    test_results = []

    # -------------------------------------------------------------
    # TEST 1: Normal HTTP Transmission
    # -------------------------------------------------------------
    print("\n[TEST 1] Normal HTTP Transmission...")
    try:
        res = requests.post(f"http://{HOST}:{HTTP_PORT}/api/transmit", json={
            "incident_id": "CC-1024",
            "message": "Unauthorized access detected in DMZ cluster.",
            "protocol": "HTTP"
        }, timeout=5.0)
        data = res.json()
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        assert data["status"] == "success"
        assert data["network_result"]["protocol"] == "HTTP"
        assert data["network_result"]["receiver_response"]["status"] == "verified"
        assert data["network_result"]["receiver_response"]["integrity"] == "VALID"
        print("  [OK] HTTP payload transmitted, verified by receiver, integrity VALID.")
        test_results.append(("TEST 1: Normal HTTP Transmission", "PASSED"))
    except Exception as e:
        print(f"  [FAIL] {str(e)}")
        all_passed = False
        test_results.append(("TEST 1: Normal HTTP Transmission", f"FAILED: {e}"))

    # -------------------------------------------------------------
    # TEST 2: Secure HTTPS Transmission with Certificate Verification
    # -------------------------------------------------------------
    print("\n[TEST 2] Secure HTTPS Transmission (TLS with Strict Certificate Verification)...")
    try:
        res = requests.post(f"http://{HOST}:{HTTP_PORT}/api/transmit", json={
            "incident_id": "CC-2048",
            "message": "Ransomware payload neutralized on subnet 10.0.4.0/24.",
            "protocol": "HTTPS"
        }, timeout=5.0)
        data = res.json()
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        assert data["status"] == "success"
        net_res = data["network_result"]
        assert net_res["protocol"] == "HTTPS"
        assert net_res["cert_verified"] is True
        assert net_res["receiver_response"]["status"] == "verified"
        assert net_res["receiver_response"]["integrity"] == "VALID"
        print("  [OK] TLS handshake established, certificate verified, packet encrypted in transit and delivered.")
        test_results.append(("TEST 2: Secure HTTPS Transmission", "PASSED"))
    except Exception as e:
        print(f"  [FAIL] {str(e)}")
        all_passed = False
        test_results.append(("TEST 2: Secure HTTPS Transmission", f"FAILED: {e}"))

    # -------------------------------------------------------------
    # TEST 3: Ciphertext Tampering Detection
    # -------------------------------------------------------------
    print("\n[TEST 3] Ciphertext Tampering Detection...")
    try:
        # First transmit a message
        transmit_res = requests.post(f"http://{HOST}:{HTTP_PORT}/api/transmit", json={
            "incident_id": "CC-3001",
            "message": "Forensic memory dump extracted.",
            "protocol": "HTTPS"
        }, timeout=5.0)
        packet = transmit_res.json()["packet"]

        # Simulate tampering
        tamper_res = requests.post(f"http://{HOST}:{HTTP_PORT}/api/simulate/tamper", json=packet, timeout=5.0)
        data = tamper_res.json()
        assert data["status"] == "tampered"
        assert data["integrity"] == "FAILED"
        exp = data["experiment"]
        assert exp["hmac_verified"] is False
        assert exp["decryption_attempted"] is False, "ciphertext reached AES before HMAC verification"
        assert exp["receiver_action"] == "REJECT_AND_DROP"
        assert "HMAC" in exp["reason"]
        print("  [OK] Ciphertext modification detected by HMAC-SHA256. Decryption aborted.")
        test_results.append(("TEST 3: Ciphertext Tampering Detection", "PASSED"))
    except Exception as e:
        print(f"  [FAIL] {str(e)}")
        all_passed = False
        test_results.append(("TEST 3: Ciphertext Tampering Detection", f"FAILED: {e}"))

    # -------------------------------------------------------------
    # TEST 4: Replay Attack Detection
    # -------------------------------------------------------------
    print("\n[TEST 4] Replay Attack Prevention...")
    try:
        # Replay the previously transmitted packet
        replay_res = requests.post(f"http://{HOST}:{HTTP_PORT}/api/simulate/replay", timeout=5.0)
        data = replay_res.json()
        assert data["status"] == "replay_simulation_complete"
        exp = data["experiment"]
        assert exp["replay_blocked"] is True
        assert exp["attack_successful"] is False
        assert exp["receiver_code"] == "REPLAY_DETECTED"
        print("  [OK] Replay detected via seen nonce cache. Duplicate message successfully rejected.")
        test_results.append(("TEST 4: Replay Attack Prevention", "PASSED"))
    except Exception as e:
        print(f"  [FAIL] {str(e)}")
        all_passed = False
        test_results.append(("TEST 4: Replay Attack Prevention", f"FAILED: {e}"))

    # -------------------------------------------------------------
    # TEST 5: Invalid TLS Certificate (MITM / Untrusted Cert)
    # -------------------------------------------------------------
    print("\n[TEST 5] Invalid TLS Certificate Verification...")
    try:
        mitm_res = requests.post(f"http://{HOST}:{HTTP_PORT}/api/simulate/mitm", timeout=5.0)
        data = mitm_res.json()
        assert data["status"] == "success"
        test_res = data["tls_certificate_verification"]
        assert test_res["success"] is False
        assert test_res["cert_verified"] is False
        assert "SSL_CERT_VERIFICATION_ERROR" in test_res["error_type"]
        print("  [OK] TLS handshake rejected untrusted certificate. SSLCertVerificationError triggered.")
        test_results.append(("TEST 5: Invalid TLS Certificate Verification", "PASSED"))
    except Exception as e:
        print(f"  [FAIL] {str(e)}")
        all_passed = False
        test_results.append(("TEST 5: Invalid TLS Certificate Verification", f"FAILED: {e}"))

    # -------------------------------------------------------------
    # TEST 6: Invalid or Missing Authentication Tag
    # -------------------------------------------------------------
    print("\n[TEST 6] Invalid / Missing Authentication Tag...")
    try:
        bad_tag_packet = dict(packet)
        bad_tag_packet["nonce"] = "fresh_nonce_for_test6"
        bad_tag_packet["hmac"] = b64_encode(b"0" * 32)  # Bogus 32-byte tag

        res = requests.post(f"http://{HOST}:{HTTP_PORT}/api/officer_b/receive", json=bad_tag_packet, timeout=5.0)
        data = res.json()
        assert res.status_code == 400
        assert data["status"] == "rejected"
        assert data["code"] == "HMAC_VERIFICATION_FAILED"
        print("  [OK] Receiver rejected forged/invalid HMAC tag before attempting decryption.")
        test_results.append(("TEST 6: Invalid or Missing Authentication Tag", "PASSED"))
    except Exception as e:
        print(f"  [FAIL] {str(e)}")
        all_passed = False
        test_results.append(("TEST 6: Invalid or Missing Authentication Tag", f"FAILED: {e}"))

    # -------------------------------------------------------------
    # TEST 7: Normal Decryption & Content Accuracy
    # -------------------------------------------------------------
    print("\n[TEST 7] Normal End-to-End Decryption Accuracy...")
    try:
        test_incident_id = "CC-9999"
        test_message = "Zero-day vulnerability patched in edge gateway."
        res = requests.post(f"http://{HOST}:{HTTP_PORT}/api/transmit", json={
            "incident_id": test_incident_id,
            "message": test_message,
            "protocol": "HTTPS"
        }, timeout=5.0)
        data = res.json()
        receiver_data = data["network_result"]["receiver_response"]
        expected_output = f"[{test_incident_id}] {test_message}"
        assert receiver_data["decrypted_message"] == expected_output, (
            f"Expected '{expected_output}', got '{receiver_data['decrypted_message']}'"
        )
        print("  [OK] Officer B decrypted and displayed the exact original incident report.")
        test_results.append(("TEST 7: Normal End-to-End Decryption Accuracy", "PASSED"))
    except Exception as e:
        print(f"  [FAIL] {str(e)}")
        all_passed = False
        test_results.append(("TEST 7: Normal End-to-End Decryption Accuracy", f"FAILED: {e}"))

    # -------------------------------------------------------------
    # TEST 8: Legacy Backward Compatibility (/api/send, /api/receive, /api/tamper)
    # -------------------------------------------------------------
    print("\n[TEST 8] Legacy Backward Compatibility (/api/send & /api/receive)...")
    try:
        legacy_msg = "CC-LEGACY | Legacy message format test"
        send_res = requests.post(f"http://{HOST}:{HTTP_PORT}/api/send", json={"message": legacy_msg}, timeout=5.0)
        assert send_res.status_code == 200
        send_data = send_res.json()
        assert send_data["status"] == "success"

        recv_res = requests.post(f"http://{HOST}:{HTTP_PORT}/api/receive", json={
            "iv": send_data["iv"],
            "ciphertext": send_data["encrypted_message"],
            "hmac": send_data["hmac"],
            "nonce": send_data["nonce"],
            "timestamp": send_data["timestamp"],
            "incident_id": send_data["incident_id"]
        }, timeout=5.0)
        assert recv_res.status_code == 200
        recv_data = recv_res.json()
        assert recv_data["status"] == "verified"
        assert recv_data["message"] == legacy_msg
        print("  [OK] Legacy endpoints remain fully functional and backward compatible.")
        test_results.append(("TEST 8: Legacy Backward Compatibility", "PASSED"))
    except Exception as e:
        print(f"  [FAIL] {str(e)}")
        all_passed = False
        test_results.append(("TEST 8: Legacy Backward Compatibility", f"FAILED: {e}"))

    print("\n" + "=" * 70)
    print("TEST SUITE SUMMARY:")
    for test_name, result in test_results:
        print(f"  {test_name.ljust(45)}: {result}")
    print("=" * 70)

    if all_passed:
        print(">>> ALL 8 END-TO-END TESTS PASSED SUCCESSFULLY! <<<")
        return 0
    else:
        print(">>> SOME TESTS FAILED! <<<")
        return 1


if __name__ == "__main__":
    code = run_tests()
    # Force exit background threads
    os._exit(code)
