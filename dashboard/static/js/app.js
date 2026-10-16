// NetSentinel - Active Threat Protection Dashboard Logic

let currentPendingModalUuid = null;

document.addEventListener("DOMContentLoaded", () => {
    initEventListeners();
    fetchDashboardData();
    setInterval(fetchDashboardData, 3000);
});

function initEventListeners() {
    // Mode Switcher Buttons
    document.querySelectorAll(".mode-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const mode = btn.dataset.mode;
            setProtectionMode(mode);
        });
    });

    // Dry Run Toggle
    document.getElementById("btnToggleDryRun").addEventListener("click", toggleDryRun);

    // Emergency Stop
    document.getElementById("btnEmergencyStop").addEventListener("click", triggerEmergencyStop);

    // Threat Simulation Form
    document.getElementById("simulateThreatForm").addEventListener("submit", handleThreatSimulation);

    // Add Allowlist Prompt
    document.getElementById("btnAddAllowlist").addEventListener("click", promptAddAllowlist);
}

async function fetchDashboardData() {
    try {
        const res = await fetch("/api/status");
        if (!res.ok) return;
        const data = await res.json();
        updateUIStatus(data);

        // Fetch sub-panels
        fetchBlockedTargets();
        fetchApprovals();
        fetchQuarantined();
        fetchDevices();
        fetchRecentActions();
        fetchAllowlist();
    } catch (e) {
        console.error("Dashboard poll error:", e);
    }
}

function updateUIStatus(data) {
    // Update Mode Display
    const modeText = document.getElementById("currentModeText");
    modeText.innerText = `MODE: ${data.protection_mode.replace("_", " ")}`;
    
    // Highlight active sidebar button
    document.querySelectorAll(".mode-btn").forEach(btn => {
        if (btn.dataset.mode === data.protection_mode) {
            btn.classList.add("active");
        } else {
            btn.classList.remove("active");
        }
    });

    // Dry-run badge
    const dryBadge = document.getElementById("dryRunBadge");
    if (data.dry_run_mode) {
        dryBadge.className = "dry-run-badge badge-active";
        dryBadge.innerHTML = '<i class="fa-solid fa-flask"></i> DRY-RUN ACTIVE';
    } else {
        dryBadge.className = "dry-run-badge badge-inactive";
        dryBadge.innerHTML = '<i class="fa-solid fa-shield"></i> LIVE ENFORCEMENT';
    }

    // Emergency Stop button text
    const btnStop = document.getElementById("btnEmergencyStop");
    if (data.emergency_stop_active) {
        btnStop.innerHTML = '<i class="fa-solid fa-play"></i> CLEAR EMERGENCY STOP';
        btnStop.classList.remove("btn-danger");
        btnStop.classList.add("btn-primary");
    } else {
        btnStop.innerHTML = '<i class="fa-solid fa-octagon-exclamation"></i> EMERGENCY STOP';
        btnStop.classList.remove("btn-primary");
        btnStop.classList.add("btn-danger");
    }

    // Counts
    document.getElementById("cntActiveBlocks").innerText = data.counts.active_blocks;
    document.getElementById("cntApprovals").innerText = data.counts.pending_approvals;
    document.getElementById("cntQuarantined").innerText = data.counts.quarantined_devices;
    document.getElementById("cntVerified").innerText = data.counts.verified_enforcements;

    // ESP32 Status
    if (data.esp32_status) {
        const espBadge = document.getElementById("esp32Badge");
        if (data.esp32_status.connected) {
            espBadge.className = "status-pill status-green";
            espBadge.innerText = "Online";
        } else {
            espBadge.className = "status-pill status-red";
            espBadge.innerText = "Offline";
        }
        document.getElementById("esp32Heartbeat").innerText = `${data.esp32_status.seconds_since_heartbeat}s ago`;
        const tamperEl = document.getElementById("esp32Tamper");
        if (data.esp32_status.tamper) {
            tamperEl.innerText = "ALERT - TRIPPED";
            tamperEl.className = "text-danger";
        } else {
            tamperEl.innerText = "SECURED";
            tamperEl.className = "text-success";
        }
    }
}

async function setProtectionMode(mode) {
    try {
        const res = await fetch("/api/protection-mode", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode: mode, operator: "ADMIN_UI" })
        });
        const d = await res.json();
        fetchDashboardData();
    } catch (e) {
        alert("Failed to change protection mode: " + e);
    }
}

async function toggleDryRun() {
    try {
        await fetch("/api/dry-run/toggle", { method: "POST" });
        fetchDashboardData();
    } catch (e) {
        alert("Failed to toggle dry-run: " + e);
    }
}

async function triggerEmergencyStop() {
    const btn = document.getElementById("btnEmergencyStop");
    const isClearing = btn.innerText.includes("CLEAR");
    const endpoint = isClearing ? "/api/emergency-stop/clear" : "/api/emergency-stop";

    if (!isClearing && !confirm("EMERGENCY STOP WARNING: This will immediately revoke ALL active firewall blocks and quarantine actions. Threat detection will remain active. Proceed?")) {
        return;
    }

    try {
        await fetch(endpoint, { method: "POST" });
        fetchDashboardData();
    } catch (e) {
        alert("Emergency stop action failed: " + e);
    }
}

async function fetchBlockedTargets() {
    try {
        const res = await fetch("/api/blocked-targets");
        const targets = await res.json();
        const tbody = document.getElementById("blockedTargetsTbody");

        const activeTargets = targets.filter(t => t.is_active);
        if (activeTargets.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No active blocks currently applied.</td></tr>`;
            return;
        }

        tbody.innerHTML = activeTargets.map(t => `
            <tr>
                <td><strong>${t.target}</strong> (${t.target_type})</td>
                <td>${t.reason}</td>
                <td><span class="badge ${t.risk_score >= 80 ? 'badge-danger' : 'badge-warning'}">${t.risk_score}</span></td>
                <td>${new Date(t.blocked_at).toLocaleTimeString()}</td>
                <td><i class="fa-regular fa-clock"></i> ${t.seconds_remaining}s</td>
                <td><span class="status-pill status-green">ACTIVE</span></td>
                <td>
                    <button class="btn btn-sm btn-secondary" onclick="unblockTarget('${t.target}')">
                        <i class="fa-solid fa-lock-open"></i> Unblock
                    </button>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("fetchBlockedTargets error:", e);
    }
}

async function unblockTarget(target) {
    if (!confirm(`Manually release active block on target ${target}?`)) return;
    try {
        await fetch(`/api/blocked-targets/${encodeURIComponent(target)}/unblock`, { method: "POST" });
        fetchBlockedTargets();
    } catch (e) {
        alert("Unblock failed: " + e);
    }
}

async function fetchApprovals() {
    try {
        const res = await fetch("/api/approvals");
        const approvals = await res.json();
        const section = document.getElementById("approvalSection");
        const list = document.getElementById("approvalRequestsList");

        if (approvals.length === 0) {
            section.style.display = "none";
            return;
        }

        section.style.display = "block";
        list.innerHTML = approvals.map(a => `
            <div class="approval-card" style="background: #252e3e; border: 1px solid #f59e0b; padding: 1rem; border-radius: 6px; margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong>Target: ${a.target}</strong> | Action: <code>${a.action_type}</code> | Risk: <span class="badge badge-danger">${a.risk_score}</span>
                        <p style="font-size: 0.8rem; color: #9ca3af; margin-top: 0.25rem;">Rule: <code>${a.proposed_rule}</code></p>
                        <p style="font-size: 0.8rem; color: #f59e0b;">Impact: ${a.potential_impact}</p>
                    </div>
                    <div style="display: flex; gap: 0.5rem;">
                        <button class="btn btn-sm btn-secondary" onclick="decideApproval('${a.request_uuid}', false)">Reject</button>
                        <button class="btn btn-sm btn-danger" onclick="openApprovalModal('${a.request_uuid}', '${a.target}', '${a.action_type}', ${a.risk_score}, '${encodeURIComponent(a.proposed_rule)}', '${encodeURIComponent(a.potential_impact)}', ${a.duration_seconds})">Review & Authorize</button>
                    </div>
                </div>
            </div>
        `).join("");
    } catch (e) {
        console.error("fetchApprovals error:", e);
    }
}

function openApprovalModal(uuid, target, action, risk, ruleEnc, impactEnc, duration) {
    currentPendingModalUuid = uuid;
    document.getElementById("modalTarget").innerText = target;
    document.getElementById("modalAction").innerText = action;
    document.getElementById("modalRisk").innerText = risk;
    document.getElementById("modalRule").innerText = decodeURIComponent(ruleEnc);
    document.getElementById("modalImpact").innerText = decodeURIComponent(impactEnc);
    document.getElementById("modalDuration").innerText = duration;
    document.getElementById("approvalModal").style.display = "flex";
}

function closeApprovalModal() {
    document.getElementById("approvalModal").style.display = "none";
    currentPendingModalUuid = null;
}

async function approveCurrentModal() {
    if (!currentPendingModalUuid) return;
    await decideApproval(currentPendingModalUuid, true);
    closeApprovalModal();
}

async function rejectCurrentModal() {
    if (!currentPendingModalUuid) return;
    await decideApproval(currentPendingModalUuid, false);
    closeApprovalModal();
}

async function decideApproval(uuid, approve) {
    try {
        await fetch(`/api/approvals/${uuid}/decide`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ approve: approve, operator: "ADMIN_OPERATOR" })
        });
        fetchApprovals();
        fetchBlockedTargets();
        fetchDashboardData();
    } catch (e) {
        alert("Approval decision error: " + e);
    }
}

async function fetchQuarantined() {
    try {
        const res = await fetch("/api/quarantined-devices");
        const devices = await res.json();
        const tbody = document.getElementById("quarantinedTbody");
        const active = devices.filter(d => d.is_active);

        if (active.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No devices currently in quarantine.</td></tr>`;
            return;
        }

        tbody.innerHTML = active.map(d => `
            <tr>
                <td><strong>${d.mac_address}</strong><br><small>${d.ip_address || ''}</small></td>
                <td>${d.quarantine_method}</td>
                <td>${d.enforcement_point}</td>
                <td>
                    <button class="btn btn-sm btn-secondary" onclick="releaseDevice('${d.mac_address}')">Release</button>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("fetchQuarantined error:", e);
    }
}

async function releaseDevice(mac) {
    if (!confirm(`Release device ${mac} from quarantine?`)) return;
    try {
        await fetch(`/api/quarantined-devices/${encodeURIComponent(mac)}/release`, { method: "POST" });
        fetchQuarantined();
        fetchDevices();
    } catch (e) {
        alert("Release failed: " + e);
    }
}

async function fetchDevices() {
    try {
        const res = await fetch("/api/devices");
        const devices = await res.json();
        const tbody = document.getElementById("deviceInventoryTbody");

        if (devices.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No LAN devices discovered yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = devices.slice(0, 10).map(d => `
            <tr>
                <td>${d.ip_address}<br><small class="text-muted">${d.hostname || ''}</small></td>
                <td><code>${d.mac_address || 'N/A'}</code></td>
                <td><span class="status-pill ${d.trust_status === 'Trusted' ? 'status-green' : 'status-amber'}">${d.trust_status}</span></td>
                <td>${d.risk_score}</td>
                <td>
                    <button class="btn btn-sm btn-secondary" onclick="setDeviceTrusted(${d.id})">Trust</button>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("fetchDevices error:", e);
    }
}

async function setDeviceTrusted(id) {
    try {
        await fetch(`/api/devices/${id}/trust-status`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: "Trusted" })
        });
        fetchDevices();
    } catch (e) {
        alert("Trust update failed: " + e);
    }
}

async function fetchRecentActions() {
    try {
        const res = await fetch("/api/actions/recent");
        const actions = await res.json();
        const tbody = document.getElementById("recentActionsTbody");

        if (actions.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted">No actions recorded.</td></tr>`;
            return;
        }

        tbody.innerHTML = actions.slice(0, 15).map(a => `
            <tr>
                <td>${new Date(a.created_at).toLocaleTimeString()}</td>
                <td><strong>${a.target}</strong></td>
                <td><code>${a.action_type}</code></td>
                <td>${a.protection_mode.split('_')[0]}</td>
                <td>${a.authorization_status}</td>
                <td><span class="badge ${a.execution_status === 'SUCCESS' ? 'badge-green' : 'badge-amber'}">${a.execution_status}</span></td>
                <td><span class="badge ${a.verification_status === 'VERIFIED' ? 'badge-green' : 'badge-red'}">${a.verification_status}</span></td>
                <td>
                    ${a.is_rolled_back ? '<span class="text-muted">Rolled Back</span>' : `
                    <button class="btn btn-sm btn-secondary" onclick="rollbackAction('${a.action_uuid}')">Rollback</button>`}
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("fetchRecentActions error:", e);
    }
}

async function rollbackAction(uuid) {
    if (!confirm("Revert this protective action and restore firewall state?")) return;
    try {
        await fetch(`/api/actions/${uuid}/rollback`, { method: "POST" });
        fetchRecentActions();
        fetchBlockedTargets();
    } catch (e) {
        alert("Rollback failed: " + e);
    }
}

async function fetchAllowlist() {
    try {
        const res = await fetch("/api/allowlist");
        const assets = await res.json();
        const container = document.getElementById("allowlistTags");
        container.innerHTML = assets.map(a => `
            <div class="asset-tag">
                <i class="fa-solid fa-shield"></i>
                <strong>${a.asset_value}</strong>
                <span>(${a.description})</span>
            </div>
        `).join("");
    } catch (e) {
        console.error("fetchAllowlist error:", e);
    }
}

async function promptAddAllowlist() {
    const val = prompt("Enter IP, Subnet, or MAC to protect:");
    if (!val) return;
    const desc = prompt("Enter description:", "Protected Server/Gateway");
    try {
        await fetch("/api/allowlist", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ asset_value: val, description: desc || "Allowlisted Asset" })
        });
        fetchAllowlist();
    } catch (e) {
        alert("Add allowlist error: " + e);
    }
}

async function handleThreatSimulation(e) {
    e.preventDefault();
    const cat = document.getElementById("simCategory").value;
    const ip = document.getElementById("simIp").value;
    const sev = parseFloat(document.getElementById("simSeverity").value);
    const ai = parseFloat(document.getElementById("simAiScore").value);

    try {
        const res = await fetch("/api/threats/ingest", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                category: cat,
                src_ip: ip,
                dst_ip: "192.168.1.10",
                ids_severity: sev,
                ai_anomaly_score: ai,
                confidence: 0.85
            })
        });
        const result = await res.json();
        alert(`Threat processed:\nScore: ${result.threat_evaluation.risk_score} (${result.threat_evaluation.severity})\nAction: ${result.response_result.action_type || 'NONE'} (${result.response_result.status || result.response_result.outcome_status})`);
        fetchDashboardData();
    } catch (err) {
        alert("Simulation failed: " + err);
    }
}
