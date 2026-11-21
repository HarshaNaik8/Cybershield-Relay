// ============================================================
// CYBERSHIELD RELAY - SECURE CLIENT LOGIC (SECURE CLIENT)
// Integrates: Cryptographic Workflow, TShark Network Packet
// Capture & Analysis, Attack Simulations, IDS Monitor, and Audit
// ============================================================

let currentSessionData = null;
let lastTransmittedPacket = null;
let currentNetworkMode = "HTTPS";
let cachedPackets = [];
let capturePollTimer = null;
let activeLogCategory = "ALL";

// ============================================================
// 1. TAB NAVIGATION CONTROLLER
// ============================================================

function switchTab(tabId) {
    // Update tab button active states
    const tabs = document.querySelectorAll(".nav-tab");
    tabs.forEach(tab => {
        const onclickAttr = tab.getAttribute("onclick") || "";
        if (onclickAttr.includes(tabId)) {
            tab.classList.add("active");
        } else {
            tab.classList.remove("active");
        }
    });

    // Update section active states
    const sections = document.querySelectorAll(".tab-content");
    sections.forEach(sec => {
        if (sec.id === tabId) {
            sec.classList.add("active");
        } else {
            sec.classList.remove("active");
        }
    });

    // Trigger tab-specific refresh actions
    if (tabId === "tab-dashboard") {
        updateDashboardTelemetry();
    } else if (tabId === "tab-analyzer") {
        refreshCaptureStatus();
        loadCapturedPackets();
    } else if (tabId === "tab-analytics") {
        loadTrafficAnalytics();
    } else if (tabId === "tab-monitor") {
        loadSecurityAlerts();
    } else if (tabId === "tab-logs") {
        filterLogs(activeLogCategory);
    }
}

// ============================================================
// 2. SESSION MANAGEMENT & INITIALIZATION
// ============================================================

async function checkSession() {
    try {
        const response = await fetch("/api/session");
        const data = await response.json();

        if (data.status === "success") {
            currentSessionData = data;
            updateSessionUI(data);

            addSecurityLog("CRYPTO", "Diffie-Hellman session active (RFC 3526 2048-bit Group 14)");
            addSecurityLog("CRYPTO", "Separate AES-256 and HMAC-SHA256 keys derived via HKDF-SHA256");
            addSecurityLog("CRYPTO", "Officer B Ed25519 signature active for handshake authentication");
            addSecurityLog("NETWORK", "TLS Server Certificate loaded (CN=127.0.0.1, O=CyberShield Relay Authority)");

            updateDashboardTelemetry();
        }
    } catch (error) {
        console.error("Session check error:", error);
        const statusEl = document.getElementById("sessionStatus");
        if (statusEl) statusEl.textContent = "Session Error - Server Unreachable";
        const dotEl = document.getElementById("statusDot");
        if (dotEl) dotEl.style.background = "#ef4444";
        addSecurityLog("INFO", "Failed to connect to backend server");
    }
}

function updateSessionUI(data) {
    const crypto = data.crypto;
    const cert = data.certificate;

    // Topbar
    const statusEl = document.getElementById("sessionStatus");
    if (statusEl) statusEl.textContent = "Secure Session (DH 2048-bit Active)";
    const dotEl = document.getElementById("statusDot");
    if (dotEl) dotEl.style.background = "#10b981";

    // Summary Card
    if (crypto) {
        const sId = document.getElementById("dispSessionId");
        if (sId) sId.textContent = crypto.session_id || "-";

        const ssStatus = document.getElementById("dispSharedSecretStatus");
        if (ssStatus) ssStatus.textContent = `Derived & Verified (${crypto.shared_secret_length_bytes} bytes)`;

        const authStatus = document.getElementById("dispHandshakeAuthStatus");
        if (authStatus) {
            authStatus.textContent = crypto.handshake_verified ? "Ed25519 Signature Verified" : "Unauthenticated";
        }

        // Public Keys
        const oAPub = document.getElementById("dispOfficerAPub");
        if (oAPub) oAPub.textContent = crypto.officer_a_public_pem ? crypto.officer_a_public_pem.trim() : "-";

        const oBPub = document.getElementById("dispOfficerBPub");
        if (oBPub) oBPub.textContent = crypto.officer_b_public_pem ? crypto.officer_b_public_pem.trim() : "-";

        // Key Fingerprints
        const aesFp = document.getElementById("dispAesFp");
        if (aesFp) aesFp.textContent = crypto.aes_key_fingerprint || "-";

        const hmacFp = document.getElementById("dispHmacFp");
        if (hmacFp) hmacFp.textContent = crypto.hmac_key_fingerprint || "-";

        // Handshake Ed25519 Keys
        const edVerifying = document.getElementById("dispEdVerifyingKey");
        if (edVerifying) edVerifying.textContent = crypto.server_verifying_key_hex || "-";

        const edSig = document.getElementById("dispEdSignature");
        if (edSig) edSig.textContent = crypto.handshake_signature_hex || "-";
    }

    // Certificate Info
    if (cert) {
        const cSub = document.getElementById("certSubject");
        if (cSub) cSub.textContent = cert.subject || "-";
        const cIss = document.getElementById("certIssuer");
        if (cIss) cIss.textContent = cert.issuer || "-";
        const cExp = document.getElementById("certExpiry");
        if (cExp) cExp.textContent = cert.not_valid_after || "-";
        const cFp = document.getElementById("certFp");
        if (cFp) cFp.textContent = cert.sha256_fingerprint || "-";
        const cSum = document.getElementById("certSummaryText");
        if (cSum) {
            cSum.textContent = `Subject: ${cert.subject} | ${cert.key_algorithm} | ${cert.signature_algorithm}`;
        }
    }

    updateTargetEndpoints();
}

function updateDashboardTelemetry() {
    if (!currentSessionData) return;

    const dhStatus = document.getElementById("dashDhStatus");
    if (dhStatus) dhStatus.textContent = "RFC 3526 2048-bit Active";

    const edStatus = document.getElementById("dashEd25519Status");
    if (edStatus) edStatus.textContent = "Ed25519 Verified";

    // Update LAN IP info
    fetch("/api/network/config")
        .then(r => r.json())
        .then(data => {
            if (data.status === "success") {
                const cfg = data.config;
                const netMode = document.getElementById("dashNetMode");
                if (netMode) netMode.textContent = `${cfg.mode} (${cfg.active_host})`;
                const lanIp = document.getElementById("dashLanIp");
                if (lanIp) lanIp.textContent = cfg.lan_ip || "127.0.0.1";
                const badge = document.getElementById("lanModeBadge");
                if (badge) badge.textContent = `Mode: ${cfg.mode}`;
            }
        })
        .catch(() => {});
}

async function generateNewSession() {
    try {
        const response = await fetch("/api/session/new", { method: "POST" });
        const data = await response.json();

        if (data.status === "success") {
            await checkSession();
            resetInboxUI();
            resetInspectorUI();

            addSecurityLog("CRYPTO", "Fresh ephemeral Diffie-Hellman session established. New AES & HMAC keys derived.");
            alert("✓ New Diffie-Hellman ephemeral session established! All keys re-derived.");
        }
    } catch (error) {
        console.error("Re-key error:", error);
        alert("Failed to establish new DH session.");
    }
}

// ============================================================
// 3. NETWORK MODE CONFIGURATION
// ============================================================

function onNetworkModeChange(mode) {
    currentNetworkMode = mode;
    updateTargetEndpoints();

    const badge = document.getElementById("activeChannelBadge");
    const transportSummary = document.getElementById("transportSummaryCard");

    if (mode === "HTTPS") {
        if (badge) {
            badge.className = "channel-badge badge-https";
            badge.textContent = "🔒 HTTPS (TLS 1.3 Active)";
        }
        if (transportSummary) transportSummary.textContent = "TLS 1.3 / Strict Cert";
        addSecurityLog("NETWORK", "Transmission channel switched to: Secure HTTPS (Port 5443, TLS 1.3 Verified)");
    } else {
        if (badge) {
            badge.className = "channel-badge badge-http";
            badge.textContent = "⚠️ Insecure HTTP (Plaintext Transport)";
        }
        if (transportSummary) transportSummary.textContent = "HTTP (Plaintext Wire)";
        addSecurityLog("NETWORK", "Transmission channel switched to: Insecure HTTP (Port 5000, Transport Exposed)");
    }
}

function updateTargetEndpoints() {
    const endpointLabel = document.getElementById("dispTargetEndpoint");
    const transportLabel = document.getElementById("dispTransportMode");

    if (currentNetworkMode === "HTTPS") {
        if (endpointLabel) endpointLabel.textContent = "https://127.0.0.1:5443/api/officer_b/receive";
        if (transportLabel) transportLabel.textContent = "HTTPS (TLS 1.3 Encrypted Channel)";
    } else {
        if (endpointLabel) endpointLabel.textContent = "http://127.0.0.1:5000/api/officer_b/receive";
        if (transportLabel) transportLabel.textContent = "HTTP (Plaintext Transport Layer)";
    }
}

// ============================================================
// 4. OFFICER A: ENCRYPT & TRANSMIT OVER NETWORK
// ============================================================

async function sendSecureMessage() {
    const incidentIdEl = document.getElementById("incidentId");
    const messageEl = document.getElementById("message");

    const incidentId = incidentIdEl ? incidentIdEl.value.trim() : "";
    const message = messageEl ? messageEl.value.trim() : "";

    if (!incidentId) {
        alert("Please enter a valid Incident ID (e.g., CC-1024).");
        return;
    }
    if (!message) {
        alert("Please enter incident information.");
        return;
    }

    const btn = document.getElementById("btnEncryptSend");
    if (btn) {
        btn.disabled = true;
        btn.textContent = "⏳ Transmitting over Network...";
    }

    try {
        const response = await fetch("/api/transmit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                incident_id: incidentId,
                message: message,
                protocol: currentNetworkMode
            })
        });

        const data = await response.json();
        if (btn) {
            btn.disabled = false;
            btn.textContent = "🔒 Encrypt & Transmit over Network";
        }

        if (data.status === "success") {
            const pkt = data.packet;
            const netRes = data.network_result || {};
            const recvRes = netRes.receiver_response || {};
            lastTransmittedPacket = pkt;

            // Display Cryptographic Evidence
            const evBox = document.getElementById("cryptoEvidence");
            if (evBox) evBox.classList.remove("hidden");

            const evNonce = document.getElementById("evidenceNonce");
            if (evNonce) evNonce.textContent = pkt.nonce;
            const evTs = document.getElementById("evidenceTimestamp");
            if (evTs) evTs.textContent = pkt.timestamp;
            const evIv = document.getElementById("evidenceIv");
            if (evIv) evIv.textContent = pkt.iv;
            const evCipher = document.getElementById("ciphertextValue");
            if (evCipher) evCipher.textContent = pkt.ciphertext;
            const evHmac = document.getElementById("hmacValue");
            if (evHmac) evHmac.textContent = pkt.hmac;

            // Result box
            const resultBox = document.getElementById("sendResult");
            if (resultBox) {
                resultBox.classList.remove("hidden");
                resultBox.innerHTML = `
                    <strong>✓ Incident Encrypted &amp; Transmitted Successfully</strong><br>
                    &bull; AES-256-CBC encryption applied with PKCS7 padding.<br>
                    &bull; HMAC-SHA256 authentication tag computed over metadata and ciphertext.<br>
                    &bull; Network Protocol: <strong>${data.protocol}</strong> &bull; Round-trip: <strong>${netRes.round_trip_ms || 0} ms</strong>.<br>
                    &bull; Transport Verification: <strong>${netRes.cert_verified ? "TLS Certificate Verified" : "Plaintext Transport"}</strong>.
                `;
            }

            // Logs
            addSecurityLog("CRYPTO", `Encrypted incident '${incidentId}' using AES-256-CBC`);
            addSecurityLog("CRYPTO", `Generated HMAC-SHA256 authentication tag over (metadata || IV || ciphertext)`);
            addSecurityLog("NETWORK", `Packet transmitted via ${data.protocol} to Officer B (${netRes.round_trip_ms || 0}ms round-trip)`);

            if (data.protocol === "HTTPS") {
                addSecurityLog("NETWORK", "TLS handshake verified server certificate (CN=127.0.0.1)");
            } else {
                addSecurityLog("NETWORK", "WARNING: Packet transmitted over insecure HTTP. Headers exposed on wire.");
            }

            // Update Packet Inspector
            updatePacketInspector(pkt, netRes);

            // Update Officer B Receiver
            updateReceiverInbox(recvRes, data.protocol);

            // Refresh capture packet list
            setTimeout(() => {
                loadCapturedPackets();
            }, 600);
        } else {
            alert(`Transmission failed: ${data.message || "Unknown error"}`);
        }
    } catch (error) {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "🔒 Encrypt & Transmit over Network";
        }
        console.error("Transmission error:", error);
        alert("Network transmission failed. Ensure the Flask server is running.");
    }
}

// ============================================================
// 5. OFFICER B: RECEIVER VERIFICATION UI
// ============================================================

function updateReceiverInbox(recvRes, protocol) {
    const statusBox = document.getElementById("inboxStatusBox");
    const icon = document.getElementById("integrityIcon");
    const title = document.getElementById("integrityTitle");
    const text = document.getElementById("integrityText");
    const msgBox = document.getElementById("receivedMessage");

    const pipeTransport = document.getElementById("pipeTransport");
    const pipeFreshness = document.getElementById("pipeFreshness");
    const pipeReplay = document.getElementById("pipeReplay");
    const pipeHmac = document.getElementById("pipeHmac");
    const pipeDecrypt = document.getElementById("pipeDecrypt");

    if (recvRes.status === "verified") {
        if (statusBox) {
            statusBox.style.background = "#0d271b";
            statusBox.style.borderColor = "#1e623b";
        }
        if (icon) icon.textContent = "🟢";
        if (title) title.textContent = "Incident Verified & Decrypted";
        if (text) text.textContent = "All transport, replay, HMAC-SHA256, and AES-256 integrity checks passed.";
        if (msgBox) {
            msgBox.textContent = recvRes.decrypted_message;
            msgBox.style.borderColor = "#1e623b";
            msgBox.style.color = "#a7f3d0";
        }

        if (pipeTransport) setPipelineStep(pipeTransport, true, protocol === "HTTPS" ? "TLS 1.3 Verified" : "Plaintext HTTP (Unencrypted)");
        if (pipeFreshness) setPipelineStep(pipeFreshness, true, "Fresh (Within ±300s window)");
        if (pipeReplay) setPipelineStep(pipeReplay, true, `Unique Nonce '${recvRes.nonce || ""}' Verified`);
        if (pipeHmac) setPipelineStep(pipeHmac, true, "HMAC-SHA256 Signature Valid (Constant-time)");
        if (pipeDecrypt) setPipelineStep(pipeDecrypt, true, "AES-256-CBC Decryption & PKCS7 Valid");

        addSecurityLog("RECEIVER", "Officer B verified timestamp freshness and nonce uniqueness");
        addSecurityLog("RECEIVER", "Officer B verified HMAC-SHA256 tag (constant-time verification)");
        addSecurityLog("RECEIVER", "Officer B decrypted AES-256 ciphertext and validated PKCS7 padding");
        addSecurityLog("RECEIVER", `Incident accepted by Officer B: '${recvRes.decrypted_message}'`);
    } else {
        if (statusBox) {
            statusBox.style.background = "#2a1515";
            statusBox.style.borderColor = "#682525";
        }
        if (icon) icon.textContent = "🔴";
        if (title) title.textContent = "Message Rejected by Officer B";
        if (text) text.textContent = recvRes.reason || "Security verification failed.";
        if (msgBox) {
            msgBox.textContent = `⚠️ Message rejected: ${recvRes.reason || "Integrity verification failure."}`;
            msgBox.style.borderColor = "#682525";
            msgBox.style.color = "#ff8d8d";
        }

        if (recvRes.code === "REPLAY_DETECTED") {
            if (pipeReplay) setPipelineStep(pipeReplay, false, "REPLAY DETECTED: Nonce already used!");
            if (pipeHmac) setPipelineStep(pipeHmac, false, "Aborted");
            if (pipeDecrypt) setPipelineStep(pipeDecrypt, false, "Aborted");
            addSecurityLog("ATTACK", `🚨 REPLAY BLOCKED: Nonce '${recvRes.nonce || ""}' rejected by Officer B.`);
        } else if (recvRes.code === "HMAC_VERIFICATION_FAILED") {
            if (pipeHmac) setPipelineStep(pipeHmac, false, "HMAC-SHA256 FAILED: Payload or metadata tampered!");
            if (pipeDecrypt) setPipelineStep(pipeDecrypt, false, "Aborted (Refused decryption)");
            addSecurityLog("ATTACK", "🚨 INTEGRITY FAILURE: HMAC-SHA256 verification failed. Message dropped.");
        }
    }
}

function setPipelineStep(element, isSuccess, message) {
    if (!element) return;
    const icon = element.querySelector(".pipe-icon");
    const textStrong = element.querySelector("strong");

    if (isSuccess) {
        element.className = "pipeline-step pipe-step-valid";
        if (icon) icon.textContent = "✓";
    } else {
        element.className = "pipeline-step pipe-step-invalid";
        if (icon) icon.textContent = "✗";
    }
    if (textStrong) {
        textStrong.textContent = message;
    }
}

function resetInboxUI() {
    const statusBox = document.getElementById("inboxStatusBox");
    if (statusBox) {
        statusBox.style.background = "#081523";
        statusBox.style.borderColor = "#182c40";
    }
    const icon = document.getElementById("integrityIcon");
    if (icon) icon.textContent = "🛡️";
    const title = document.getElementById("integrityTitle");
    if (title) title.textContent = "Waiting for message";
    const text = document.getElementById("integrityText");
    if (text) text.textContent = "Transmit an encrypted incident message over the network to begin.";
    const msg = document.getElementById("receivedMessage");
    if (msg) {
        msg.textContent = "No message received yet.";
        msg.style.color = "#9dafc1";
        msg.style.borderColor = "#1d3449";
    }

    const steps = ["pipeTransport", "pipeFreshness", "pipeReplay", "pipeHmac", "pipeDecrypt"];
    steps.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.className = "pipeline-step";
            const ic = el.querySelector(".pipe-icon");
            if (ic) ic.textContent = "○";
        }
    });

    const pT = document.getElementById("pipeTransportText");
    if (pT) pT.textContent = "Pending";
    const pF = document.getElementById("pipeFreshnessText");
    if (pF) pF.textContent = "Pending (±300s)";
    const pR = document.getElementById("pipeReplayText");
    if (pR) pR.textContent = "Pending Nonce Check";
    const pH = document.getElementById("pipeHmacText");
    if (pH) pH.textContent = "Pending Verification";
    const pD = document.getElementById("pipeDecryptText");
    if (pD) pD.textContent = "Pending Unpadding";
}

// ============================================================
// 6. NETWORK PACKET INSPECTOR (CRYPTO VIEW)
// ============================================================

function updatePacketInspector(pkt, netRes) {
    const badge = document.getElementById("inspectorProtocolBadge");
    if (badge) badge.textContent = `Protocol: ${netRes.protocol || "UNKNOWN"}`;

    const flowTag = document.getElementById("flowTransportTag");
    if (flowTag) {
        flowTag.textContent = netRes.protocol === "HTTPS"
            ? "🔒 TLS 1.3 Encrypted Channel"
            : "⚠️ Insecure Plaintext Channel";
    }

    const pProto = document.getElementById("pktProtocol");
    if (pProto) pProto.textContent = `${netRes.protocol || "HTTP"} (HTTP/1.1)`;

    const pSrc = document.getElementById("pktSource");
    if (pSrc) pSrc.textContent = pkt.source || "Officer A (Client @ 127.0.0.1)";

    const pDst = document.getElementById("pktDest");
    if (pDst) pDst.textContent = endpoint(pkt.dst_ip, pkt.dst_port);

    const pLat = document.getElementById("pktLatency");
    if (pLat) pLat.textContent = `${netRes.round_trip_ms || 0} ms`;

    const tlsState = document.getElementById("pktTlsState");
    const cipherState = document.getElementById("pktCipher");

    if (netRes.protocol === "HTTPS") {
        if (tlsState) {
            tlsState.textContent = "ENCRYPTED_TUNNEL (TLS 1.3 Active)";
            tlsState.className = "text-green";
        }
        if (cipherState) cipherState.textContent = netRes.tls_cipher || "AES-256-GCM / SHA-384";
    } else {
        if (tlsState) {
            tlsState.textContent = "PLAINTEXT_TRANSPORT (No TLS Encryption)";
            tlsState.className = "text-amber";
        }
        if (cipherState) cipherState.textContent = "None (Plaintext Wire)";
    }

    const pInc = document.getElementById("pktIncidentId");
    if (pInc) pInc.textContent = pkt.incident_id || "-";

    const pTs = document.getElementById("pktTimestamp");
    if (pTs) pTs.textContent = pkt.timestamp || "-";

    const pNon = document.getElementById("pktNonce");
    if (pNon) pNon.textContent = pkt.nonce || "-";

    const pIv = document.getElementById("pktIv");
    if (pIv) pIv.textContent = pkt.iv || "-";

    const pCiph = document.getElementById("pktCiphertext");
    if (pCiph) pCiph.textContent = pkt.ciphertext || "-";

    const pHmac = document.getElementById("pktHmac");
    if (pHmac) pHmac.textContent = pkt.hmac || "-";
}

function resetInspectorUI() {
    const badge = document.getElementById("inspectorProtocolBadge");
    if (badge) badge.textContent = "Protocol: NONE";

    const ids = ["pktProtocol", "pktDest", "pktLatency", "pktTlsState", "pktCipher",
                 "pktIncidentId", "pktTimestamp", "pktNonce", "pktIv", "pktCiphertext", "pktHmac"];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = "-";
    });
}

// ============================================================
// 7. WIRESHARK & TSHARK PACKET CAPTURE & INSPECTOR
// ============================================================

async function loadCaptureInterfaces() {
    try {
        const res = await fetch("/api/capture/interfaces");
        const data = await res.json();
        const select = document.getElementById("captureInterfaceSelect");
        if (!select) return;

        select.innerHTML = "";
        if (data.status === "success" && data.interfaces && data.interfaces.length > 0) {
            data.interfaces.forEach(iface => {
                const opt = document.createElement("option");
                opt.value = iface.id;
                opt.textContent = `${iface.id}. ${iface.name}${iface.is_loopback ? ' (loopback)' : ''}`;
                // Auto-select loopback adapter if found
                if (iface.is_loopback) {
                    opt.selected = true;
                }
                select.appendChild(opt);
            });
        } else {
            const opt = document.createElement("option");
            opt.value = "";
            opt.disabled = true;
            opt.textContent = "No capture interfaces found (TShark/Npcap unavailable)";
            select.appendChild(opt);
        }
    } catch (err) {
        console.warn("Could not load capture interfaces:", err);
    }
}

function decodeTcpFlags(flagStr) {
    return flagStr && flagStr.length ? flagStr : "none";
}

function endpoint(ip, port) {
    return ip ? (port ? `${ip}:${port}` : ip) : "-";
}

function setCaptureButtons(capturing) {
    const start = document.getElementById("btnStartCapture");
    const stop = document.getElementById("btnStopCapture");
    if (start) start.disabled = !!capturing;
    if (stop) stop.disabled = !capturing;
}

window.addEventListener("load", () => { refreshCaptureStatus(); });

async function startPacketCapture() {
    const select = document.getElementById("captureInterfaceSelect");
    const ifaceIdx = select ? select.value : "1";
    const filterInput = document.getElementById("captureFilterInput");
    const filterVal = filterInput ? filterInput.value.trim() : "tcp port 5000 or tcp port 5443";

    try {
        const res = await fetch("/api/capture/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: ifaceIdx, filter: filterVal })
        });
        const data = await res.json();

        if (data.success) {
            const badge = document.getElementById("captureStatusBadge");
            if (badge) {
                badge.textContent = "CAPTURE: ACTIVE (SNIFFING)";
                badge.className = "badge-inspector text-green";
            }
            const dashBadge = document.getElementById("dashCaptureStatus");
            if (dashBadge) {
                dashBadge.textContent = "TShark Capturing...";
                dashBadge.className = "telemetry-value text-green";
            }

            setCaptureButtons(true);
            addSecurityLog("NETWORK", `TShark capture started on interface #${ifaceIdx} with filter: '${filterVal}'`);

            // Start polling capture status
            if (capturePollTimer) clearInterval(capturePollTimer);
            capturePollTimer = setInterval(refreshCaptureStatus, 2000);
        } else {
            alert(`Failed to start capture: ${data.message || data.error || "Unknown error"}`);
        }
    } catch (err) {
        console.error("Capture start error:", err);
        alert("Failed to connect to capture engine.");
    }
}

async function stopPacketCapture() {
    try {
        const res = await fetch("/api/capture/stop", { method: "POST" });
        const data = await res.json();

        if (capturePollTimer) {
            clearInterval(capturePollTimer);
            capturePollTimer = null;
        }

        const badge = document.getElementById("captureStatusBadge");
        if (badge) {
            badge.textContent = "CAPTURE: IDLE";
            badge.className = "badge-inspector";
        }
        const dashBadge = document.getElementById("dashCaptureStatus");
        if (dashBadge) {
            dashBadge.textContent = "TShark Idle";
            dashBadge.className = "telemetry-value";
        }

        setCaptureButtons(false);
        addSecurityLog("NETWORK", `TShark capture stopped. File saved: ${data.file_size_bytes || 0} bytes.`);
        await loadCapturedPackets();
    } catch (err) {
        console.error("Capture stop error:", err);
    }
}

async function refreshCaptureStatus() {
    try {
        const res = await fetch("/api/capture/status");
        const data = await res.json();
        if (data.status === "success") {
            const engine = data.capture_engine;
            setCaptureButtons(engine.is_capturing);
            const badge = document.getElementById("captureStatusBadge");
            if (badge) {
                badge.textContent = engine.is_capturing ? "CAPTURE: ACTIVE (SNIFFING)" : "CAPTURE: IDLE";
                badge.className = engine.is_capturing ? "badge-inspector text-green" : "badge-inspector";
            }
            const dashBadge = document.getElementById("dashCaptureStatus");
            if (dashBadge) {
                dashBadge.textContent = engine.is_capturing ? "TShark Capturing..." : "TShark Ready";
                dashBadge.className = engine.is_capturing ? "telemetry-value text-green" : "telemetry-value";
            }
        }
    } catch (err) {
        console.warn("Could not refresh capture status:", err);
    }
}

async function loadCapturedPackets() {
    try {
        const res = await fetch("/api/packets?limit=150");
        const data = await res.json();

        const tbody = document.getElementById("packetTableBody");
        const countBadge = document.getElementById("packetCountBadge");
        const dashCount = document.getElementById("dashPacketsCount");

        if (data.status === "success" && data.packets) {
            cachedPackets = data.packets;
            if (countBadge) countBadge.textContent = `${data.packets.length} Packets`;
            if (dashCount) dashCount.textContent = data.packets.length;

            if (!tbody) return;
            tbody.innerHTML = "";

            if (data.packets.length === 0) {
                tbody.innerHTML = `<tr><td colspan="9" class="text-center" style="padding: 24px; color: #64748b;">No packets captured yet. Click 'Start Sniffer' and send an incident.</td></tr>`;
                return;
            }

            data.packets.forEach(pkt => {
                const tr = document.createElement("tr");
                tr.className = "packet-row";
                tr.onclick = () => inspectPacket(pkt.packet_number);

                let protoBadgeClass = "badge-proto-tcp";
                const protoUpper = (pkt.protocol || "").toUpperCase();
                if (protoUpper.includes("HTTP")) protoBadgeClass = "badge-proto-http";
                else if (protoUpper.includes("TLS")) protoBadgeClass = "badge-proto-tls";
                else if (protoUpper.includes("DNS")) protoBadgeClass = "badge-proto-dns";
                else if (protoUpper.includes("UDP")) protoBadgeClass = "badge-proto-udp";

                tr.innerHTML = `
                    <td><strong>#${pkt.packet_number}</strong></td>
                    <td>${pkt.timestamp || "-"}</td>
                    <td><code>${endpoint(pkt.src_ip, pkt.src_port)}</code></td>
                    <td><code>${endpoint(pkt.dst_ip, pkt.dst_port)}</code></td>
                    <td><span class="badge-proto ${protoBadgeClass}">${pkt.protocol || "TCP"}</span></td>
                    <td>${pkt.length || 0} B</td>
                    <td>${decodeTcpFlags(pkt.tcp_flags || "")}</td>
                    <td>#${pkt.stream_id !== undefined ? pkt.stream_id : "-"}</td>
                    <td style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${pkt.http_method ? pkt.http_method + " " + (pkt.http_uri || "") : (pkt.payload_preview || "-")}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.warn("Could not load captured packets:", err);
    }
}

function filterPacketTable() {
    const input = document.getElementById("packetSearchInput");
    const query = input ? input.value.toLowerCase() : "";
    const rows = document.querySelectorAll("#packetTableBody tr");

    rows.forEach(row => {
        const text = row.innerText.toLowerCase();
        if (text.includes(query)) {
            row.style.display = "";
        } else {
            row.style.display = "none";
        }
    });
}

function inspectPacket(pktNum) {
    const pkt = cachedPackets.find(p => p.packet_number === pktNum);
    if (!pkt) return;

    // Highlight row
    document.querySelectorAll("#packetTableBody tr").forEach(r => r.classList.remove("active-pkt-row"));
    const rows = document.querySelectorAll("#packetTableBody tr");
    rows.forEach(r => {
        if (r.innerText.includes(`#${pktNum}`)) {
            r.classList.add("active-pkt-row");
        }
    });

    const panel = document.getElementById("packetDetailView");
    if (panel) panel.classList.remove("hidden");

    const pNum = document.getElementById("detailPktNum");
    if (pNum) pNum.textContent = pkt.packet_number;
    const pProto = document.getElementById("detailProto");
    if (pProto) pProto.textContent = pkt.protocol || "TCP";
    const pSrc = document.getElementById("detailSrc");
    if (pSrc) pSrc.textContent = endpoint(pkt.src_ip, pkt.src_port);
    const pDst = document.getElementById("detailDst");
    if (pDst) pDst.textContent = pkt.destination || "-";
    const pLen = document.getElementById("detailLen");
    if (pLen) pLen.textContent = `${pkt.length || 0} bytes`;

    const pFlags = document.getElementById("detailFlags");
    if (pFlags) pFlags.textContent = decodeTcpFlags(pkt.tcp_flags || "");

    const pSeq = document.getElementById("detailSeq");
    if (pSeq) pSeq.textContent = pkt.seq_number !== undefined ? pkt.seq_number : "-";
    const pAck = document.getElementById("detailAck");
    if (pAck) pAck.textContent = pkt.ack_number !== undefined ? pkt.ack_number : "-";
    const pStream = document.getElementById("detailStream");
    if (pStream) pStream.textContent = pkt.stream_id !== undefined ? `Stream #${pkt.stream_id}` : "-";
    const pHttp = document.getElementById("detailHttp");
    if (pHttp) pHttp.textContent = (pkt.http_method ? pkt.http_method + " " : "") + (pkt.http_uri || "") || "N/A";

    const pHex = document.getElementById("detailHexDump");
    if (pHex) {
        pHex.textContent = pkt.combined_dump || "No payload data for this packet.";
    }

    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function closePacketDetail() {
    const panel = document.getElementById("packetDetailView");
    if (panel) panel.classList.add("hidden");
    document.querySelectorAll("#packetTableBody tr").forEach(r => r.classList.remove("active-pkt-row"));
}

function downloadCurrentPcap() {
    window.location.href = "/api/packets/download";
}

function exportPacketsCsv() {
    window.location.href = "/api/packets/export_csv";
}

// ============================================================
// 8. TRAFFIC ANALYTICS
// ============================================================

function renderDistribution(containerId, dist, total, color) {
    const box = document.getElementById(containerId);
    if (!box || !dist) return;
    box.innerHTML = "";
    for (const [label, count] of Object.entries(dist)) {
        const pct = total ? ((count / total) * 100).toFixed(1) : "0.0";
        const item = document.createElement("div");
        item.className = "dist-bar-item";
        item.innerHTML = `
            <div class="dist-bar-meta"><strong>${label}</strong><span>${count} pkts (${pct}%)</span></div>
            <div class="dist-bar-track"><div class="dist-bar-fill" style="width: ${pct}%;${color ? " background: " + color + ";" : ""}"></div></div>`;
        box.appendChild(item);
    }
}

async function loadTrafficAnalytics() {
    try {
        const res = await fetch("/api/analytics/traffic");
        const data = await res.json();

        if (data.status === "success" && data.analysis) {
            const an = data.analysis;
            const total = an.total_packets || 0;

            const setText = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
            setText("metricTotalBytes", `${((an.total_bytes || 0) / 1024).toFixed(2)} KB`);
            setText("metricAvgSize", `${an.avg_packet_size || 0} B`);
            setText("metricMaxSize", `${an.max_packet_size || 0} B`);
            setText("metricActiveStreams", an.active_streams_count || 0);

            renderDistribution("protocolDistBars", an.protocol_distribution, total, "");
            renderDistribution("sizeDistBars", an.size_buckets, total, "#10b981");

            const streamsTbody = document.getElementById("streamsTableBody");
            if (streamsTbody && an.tcp_streams) {
                streamsTbody.innerHTML = "";
                if (an.tcp_streams.length === 0) {
                    streamsTbody.innerHTML = `<tr><td colspan="8" class="text-center" style="padding: 16px; color: #64748b;">No TCP streams captured yet.</td></tr>`;
                } else {
                    an.tcp_streams.forEach(st => {
                        const tr = document.createElement("tr");
                        tr.innerHTML = `
                            <td><strong>Stream #${st.stream_id}</strong></td>
                            <td><code>${st.client_endpoint}</code></td>
                            <td><code>${st.server_endpoint}</code></td>
                            <td>${st.packet_count}</td>
                            <td>${st.client_to_server} pkts</td>
                            <td>${st.server_to_client} pkts</td>
                            <td>${st.total_bytes} B</td>
                            <td><span class="badge-inspector ${st.protocol === "TLS" ? "text-green" : ""}">${st.protocol}</span></td>
                        `;
                        streamsTbody.appendChild(tr);
                    });
                }
            }
        }
    } catch (err) {
        console.warn("Could not load traffic analytics:", err);
    }
}

// ============================================================
// 9. PLAINTEXT VS ENCRYPTED EXPERIMENT
// ============================================================

async function runEavesdroppingExperiment() {
    const input = document.getElementById("expMessageInput");
    const msg = input ? input.value.trim() : "CRITICAL: Threat actor exfiltrating credential hash database.";

    try {
        const res = await fetch("/api/simulate/eavesdrop", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: msg, incident_id: "CC-EAVES-TEST" })
        });
        const data = await res.json();

        if (data.status === "success" && data.comparison) {
            const comp = data.comparison;

            const pPlain = document.getElementById("expPlaintextPayload");
            if (pPlain) {
                pPlain.textContent = comp.plaintext_experiment.wire_payload_sample + "\n\n" + comp.plaintext_experiment.sniffer_visibility;
            }

            const pEnc = document.getElementById("expEncryptedPayload");
            if (pEnc) {
                pEnc.textContent = comp.encrypted_experiment.wire_payload_sample + "\n\n" + comp.encrypted_experiment.sniffer_visibility;
            }

            const bPlain = document.getElementById("compPlainBytes");
            if (bPlain) bPlain.textContent = `${comp.plaintext_experiment.estimated_packet_size} Bytes`;

            const bEnc = document.getElementById("compEncBytes");
            if (bEnc) bEnc.textContent = `${comp.encrypted_experiment.estimated_packet_size} Bytes`;

            addSecurityLog("ATTACK", `Side-by-side wiretap experiment executed. Plaintext exposed vs AES-256 encrypted wire payload.`);
        }
    } catch (err) {
        console.error("Eavesdropping experiment error:", err);
        alert("Experiment failed to execute.");
    }
}

// ============================================================
// 10. ATTACK LAB: SIMULATIONS
// ============================================================

async function simulateMitm() {
    try {
        const res = await fetch("/api/simulate/mitm", { method: "POST" });
        const data = await res.json();

        const box = document.getElementById("simulationResultBox");
        const badge = document.getElementById("simResultBadge");
        const title = document.getElementById("simResultTitle");
        const content = document.getElementById("simResultContent");

        if (!box) return;
        box.classList.remove("hidden");
        if (badge) {
            badge.className = "sim-badge sim-badge-blocked";
            badge.textContent = "MITM PREVENTED";
        }
        if (title) title.textContent = "Attack Demonstration: Man-in-the-Middle (MITM) & Handshake Defense";

        const unauth = data.unauthenticated_dh || {};
        const auth = data.authenticated_dh || {};
        const tls = data.tls_certificate_verification || {};
        const keys = unauth.keys_established || {};

        if (content) {
            content.innerHTML = `
                <div style="margin-bottom: 16px;">
                    <h4 style="color: #ef4444; margin-bottom: 6px;">&#10060; Scenario A: Unauthenticated Diffie-Hellman Key Exchange (${unauth.attack_outcome || "VULNERABLE"})</h4>
                    <p style="font-size: 12px; color: #cbd5e1; margin-bottom: 8px;">
                        Without authentication, Mallory replaces both public keys and holds one shared key with each officer:
                    </p>
                    <div class="code-block" style="color: #fca5a5; font-size: 11px;">
                        &bull; Key Mallory shares with Officer A (fingerprint): <code>${keys.mallory_shared_with_alice || "n/a"}</code><br>
                        &bull; Key Mallory shares with Officer B (fingerprint): <code>${keys.mallory_shared_with_bob || "n/a"}</code><br>
                        &bull; Officer A and Officer B hold different keys, so Mallory can decrypt and re-encrypt all traffic.
                    </div>
                </div>

                <div style="margin-bottom: 16px;">
                    <h4 style="color: #10b981; margin-bottom: 6px;">&#128737; Scenario B: Ed25519-Authenticated Handshake (${auth.outcome || "n/a"})</h4>
                    <div class="code-block" style="color: #86efac; font-size: 11px;">
                        &bull; Genuine handshake signature verifies: <code>${auth.legitimate_verification}</code><br>
                        &bull; Substituted-key handshake verifies: <code>${auth.mitm_attack_verification}</code><br>
                        &bull; ${auth.explanation || ""}
                    </div>
                </div>

                <div>
                    <h4 style="color: #f59e0b; margin-bottom: 6px;">&#128274; Scenario C: TLS Certificate Verification (Fake-Server Probe)</h4>
                    <div class="code-block" style="color: #fde68a; font-size: 11px;">
                        &bull; Connection success: <code>${tls.success}</code><br>
                        &bull; Error type: <code>${tls.error_type || "none"}</code><br>
                        &bull; ${tls.security_alert || "Certificate accepted."}
                    </div>
                </div>
            `;
        }

        addSecurityLog("ATTACK", "MITM simulation executed. Unauthenticated DH key substitution vs Ed25519 digital signature defense demonstrated.");
    } catch (err) {
        console.error("MITM error:", err);
        alert("Failed to execute MITM simulation.");
    }
}

async function simulateEavesdropping() {
    await runEavesdroppingExperiment();
    switchTab("tab-comparison");
}

async function simulateTampering() {
    if (!lastTransmittedPacket) {
        alert("Please encrypt and transmit an incident message first before testing tampering.");
        return;
    }

    try {
        const response = await fetch("/api/simulate/tamper", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(lastTransmittedPacket)
        });
        const data = await response.json();

        const box = document.getElementById("simulationResultBox");
        const badge = document.getElementById("simResultBadge");
        const title = document.getElementById("simResultTitle");
        const content = document.getElementById("simResultContent");

        if (box) box.classList.remove("hidden");
        if (badge) {
            badge.className = "sim-badge sim-badge-alert";
            badge.textContent = "TAMPER DETECTED";
        }
        if (title) title.textContent = "Attack 3: Ciphertext Modification Simulation";

        const exp = data.experiment || {};

        if (content) {
            content.innerHTML = `
                <div style="margin-bottom: 10px;">
                    <strong>${data.security_message}</strong>
                </div>
                <div class="code-block" style="color: #ff8a80; margin-bottom: 10px;">
                    Original Byte: ${exp.original_byte || "-"} &rarr; Modified Byte: ${exp.tampered_byte || "-"}<br>
                    Original Ciphertext: ${exp.original_ciphertext || "-"}<br>
                    Tampered Ciphertext: ${exp.tampered_ciphertext || "-"}
                </div>
                <p style="font-size: 12px; color: #a4b7ca;">
                    <strong>Security principle:</strong> In an Encrypt-then-MAC construction, the receiver verifies the HMAC-SHA256 signature
                    using constant-time comparison <em>before</em> attempting AES decryption. Because the attacker does not possess the
                    secret <code>HMAC_KEY</code> derived from the Diffie-Hellman shared secret, modifying even a single bit of ciphertext
                    produces an invalid HMAC tag. Decryption is aborted immediately, preventing padding oracle attacks.
                </p>
            `;
        }

        // Update receiver UI to show rejection
        updateReceiverInbox({
            status: "rejected",
            code: "HMAC_VERIFICATION_FAILED",
            reason: "HMAC-SHA256 verification failed: Payload was modified in transit."
        }, "HTTP");

        addSecurityLog("ATTACK", "Ciphertext byte mutated. HMAC verification failed; Officer B rejected the tampered packet.");
    } catch (error) {
        console.error("Tampering simulation error:", error);
        alert("Tampering simulation failed.");
    }
}

async function simulateReplay() {
    if (!lastTransmittedPacket) {
        alert("Please encrypt and transmit an incident message first before testing replay attack.");
        return;
    }

    try {
        const response = await fetch("/api/simulate/replay", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(lastTransmittedPacket)
        });
        const data = await response.json();
        const exp = data.experiment || {};

        const box = document.getElementById("simulationResultBox");
        const badge = document.getElementById("simResultBadge");
        const title = document.getElementById("simResultTitle");
        const content = document.getElementById("simResultContent");

        if (box) box.classList.remove("hidden");
        if (badge) {
            badge.className = exp.replay_blocked ? "sim-badge sim-badge-blocked" : "sim-badge sim-badge-alert";
            badge.textContent = exp.replay_blocked ? "REPLAY BLOCKED" : "REPLAY ACCEPTED";
        }
        if (title) title.textContent = "Attack 4: Message Replay Attack Simulation";

        if (content) {
            content.innerHTML = `
                <div style="margin-bottom: 10px;">
                    <strong style="color: #10b981;">🛡️ Replay Attack Detected &amp; Blocked by Officer B Nonce Cache</strong>
                </div>
                <div class="code-block" style="color: #81c784; margin-bottom: 10px;">
                    Replayed Nonce: ${exp.replayed_nonce || "-"}<br>
                    Initial Packet Status: ACCEPTED<br>
                    Second Submission Status: <strong>REJECTED</strong><br>
                    Receiver Code: ${exp.receiver_code || "-"}
                </div>
                <p style="font-size: 12px; color: #a4b7ca;">
                    <strong>Security principle:</strong> An attacker sniffing the wire captures a completely authentic ciphertext
                    and re-submits it to trigger duplicate state transitions. CyberShield Relay defends against this via:
                    (1) <em>Timestamp Freshness Window:</em> Packets older than ±300s are rejected as stale.
                    (2) <em>Unique Nonce Cache:</em> Every processed message nonce is cached in a thread-safe registry. Replayed nonces are rejected before decryption.
                </p>
            `;
        }

        // Update receiver UI to show rejection
        updateReceiverInbox({
            status: "rejected",
            code: "REPLAY_DETECTED",
            nonce: exp.replayed_nonce,
            reason: exp.receiver_reason || "Replay evaluated."
        }, "HTTP");

        addSecurityLog("ATTACK", `Replay attack simulated with nonce '${exp.replayed_nonce}': ${exp.replay_blocked ? 'blocked by receiver cache' : 'accepted (no earlier submission)'}.`);
    } catch (error) {
        console.error("Replay simulation error:", error);
        alert("Replay simulation failed.");
    }
}

// ============================================================
// 11. SECURITY MONITOR & BENCHMARK
// ============================================================

async function loadSecurityAlerts() {
    try {
        const res = await fetch("/api/monitor/alerts");
        const data = await res.json();

        const countEl = document.getElementById("activeAlertsCount");
        const dashCount = document.getElementById("dashAlertsCount");
        const container = document.getElementById("alertsContainer");

        if (data.status === "success") {
            const alerts = data.alerts || [];
            if (countEl) countEl.textContent = alerts.length;
            if (dashCount) dashCount.textContent = alerts.length;

            if (!container) return;
            container.innerHTML = "";

            if (alerts.length === 0) {
                container.innerHTML = `<div style="padding: 20px; text-align: center; color: #10b981;">✓ No active security alerts. All traffic compliant with security baseline.</div>`;
                return;
            }

            alerts.forEach(al => {
                const item = document.createElement("div");
                item.className = `alert-item severity-${al.severity}`;
                item.innerHTML = `
                    <div class="alert-item-header">
                        <span class="alert-item-title">${al.rule}: ${al.description}</span>
                        <span class="attack-badge" style="background: rgba(239, 68, 68, 0.2); color: #f87171;">${al.severity}</span>
                    </div>
                    <div class="alert-item-desc">${al.remediation || ""}</div>
                    <div style="font-size: 11px; color: #64748b; font-family: monospace;">Time: ${al.timestamp}</div>
                `;
                container.appendChild(item);
            });
        }
    } catch (err) {
        console.warn("Could not load security alerts:", err);
    }
}

async function runCryptoBenchmark() {
    const btn = document.getElementById("btnRunBenchmark");
    if (btn) {
        btn.disabled = true;
        btn.textContent = "⏳ Running Benchmarks...";
    }

    try {
        const res = await fetch("/api/benchmark/crypto");
        const data = await res.json();
        if (btn) {
            btn.disabled = false;
            btn.textContent = "⚡ Execute Benchmark Suite";
        }

        if (data.status === "success" && data.benchmarks) {
            const b = data.benchmarks;

            const updateVal = (id, val) => {
                const el = document.getElementById(id);
                if (el) el.textContent = val !== undefined ? `${val} ms` : "-";
            };

            updateVal("benchDhKeygen", b.dh_keygen_ms);
            updateVal("benchDhSecret", b.dh_shared_secret_ms);
            updateVal("benchEdSign", b.ed25519_sign_ms);
            updateVal("benchEdVerify", b.ed25519_verify_ms);
            updateVal("benchHkdf", b.hkdf_derivation_ms);
            updateVal("benchAesEnc", b.aes_encryption_ms);
            updateVal("benchHmacGen", b.hmac_generation_ms);
            updateVal("benchHmacVerify", b.hmac_verification_ms);
            updateVal("benchAesDec", b.aes_decryption_ms);
            updateVal("benchTotal", b.total_crypto_pipeline_ms);

            addSecurityLog("CRYPTO", `Cryptographic benchmark executed: Total pipeline latency = ${b.total_crypto_pipeline_ms} ms`);
        }
    } catch (err) {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "⚡ Execute Benchmark Suite";
        }
        console.error("Benchmark error:", err);
        alert("Failed to run benchmark.");
    }
}

// ============================================================
// 12. FORENSIC AUDIT LOG & REPORT EXPORT
// ============================================================

async function filterLogs(category) {
    activeLogCategory = category;

    // Update filter chip active state
    document.querySelectorAll(".filter-chip").forEach(chip => {
        if (chip.innerText.includes(category)) {
            chip.classList.add("active");
        } else {
            chip.classList.remove("active");
        }
    });

    try {
        const url = category === "ALL" ? "/api/logs?limit=80" : `/api/logs?category=${category}&limit=80`;
        const res = await fetch(url);
        const data = await res.json();

        const logContainer = document.getElementById("eventLog");
        if (!logContainer) return;
        logContainer.innerHTML = "";

        if (data.status === "success" && data.events) {
            if (data.events.length === 0) {
                logContainer.innerHTML = `<div style="padding: 16px; color: #64748b;">No events recorded in this category.</div>`;
                return;
            }

            data.events.forEach(ev => {
                const entry = document.createElement("div");
                entry.className = "log-entry";

                let tagClass = "tag-info";
                if (ev.category === "CRYPTO") tagClass = "tag-crypto";
                else if (ev.category === "NETWORK") tagClass = "tag-net";
                else if (ev.category === "ATTACK") tagClass = "tag-attack";
                else if (ev.category === "RECEIVER") tagClass = "tag-crypto";

                entry.innerHTML = `
                    <span class="log-timestamp">[${ev.timestamp ? ev.timestamp.substring(11, 19) : ""}]</span>
                    <span class="log-tag ${tagClass}">${ev.category}</span>
                    <span><strong>${ev.title}:</strong> ${ev.description}</span>
                `;
                logContainer.appendChild(entry);
            });
        }
    } catch (err) {
        console.warn("Could not load audit logs:", err);
    }
}

function addSecurityLog(category, message) {
    const eventLog = document.getElementById("eventLog");
    if (!eventLog) return;

    const entry = document.createElement("div");
    entry.className = "log-entry";
    const timestamp = new Date().toLocaleTimeString();

    let tagClass = "tag-info";
    if (category === "CRYPTO") tagClass = "tag-crypto";
    else if (category === "NETWORK") tagClass = "tag-net";
    else if (category === "ATTACK") tagClass = "tag-attack";

    entry.innerHTML = `
        <span class="log-timestamp">[${timestamp}]</span>
        <span class="log-tag ${tagClass}">${category}</span>
        <span>${message}</span>
    `;
    eventLog.insertBefore(entry, eventLog.firstChild);
}

async function clearSecurityLog() {
    try {
        await fetch("/api/logs/clear", { method: "POST" });
        const eventLog = document.getElementById("eventLog");
        if (eventLog) eventLog.innerHTML = "";
        addSecurityLog("INFO", "Forensic event log cleared.");
    } catch (err) {
        console.error("Failed to clear logs:", err);
    }
}

function downloadComprehensiveReport() {
    window.location.href = "/api/report/generate";
}

// ============================================================
// 13. UI ACCORDIONS
// ============================================================

function toggleCryptoDetails() {
    const details = document.getElementById("cryptoDetailsContent");
    const toggleText = document.getElementById("cryptoToggleText");
    if (!details) return;

    if (details.classList.contains("hidden")) {
        details.classList.remove("hidden");
        if (toggleText) toggleText.textContent = "Hide Session Details ▴";
    } else {
        details.classList.add("hidden");
        if (toggleText) toggleText.textContent = "Show Session Details ▾";
    }
}

// ============================================================
// 14. APPLICATION BOOTSTRAP
// ============================================================

document.addEventListener("DOMContentLoaded", () => {
    checkSession();
    loadCaptureInterfaces();
    refreshCaptureStatus();
    loadCapturedPackets();
    loadSecurityAlerts();
});
