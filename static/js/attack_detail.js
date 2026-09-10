/**
 * static/js/attack_detail.js — Client logic for dedicated attack intelligence pages.
 * Handles live telemetry, incident history fetching, and interactive safe simulation execution.
 */

document.addEventListener('DOMContentLoaded', () => {
    if (!IDS.requireAuth()) return;

    // Determine current attack slug and type key
    const path = window.location.pathname;
    let slug = '';
    const match = path.match(/\/attacks\/([a-z0-9-]+)(?:\.html)?/i);
    if (match) {
        slug = match[1];
    } else {
        const urlParams = new URLSearchParams(window.location.search);
        slug = urlParams.get('type') || 'port-scan';
    }

    // Normalized type key mapping
    const slugToKey = {
        'port-scan': 'port_scan',
        'brute-force': 'brute_force',
        'syn-flood': 'syn_flood',
        'sql-injection': 'sql_injection',
        'xss': 'xss',
        'log4shell': 'log4shell',
        'cloud-ssrf': 'cloud_ssrf',
        'path-traversal': 'path_traversal',
        'php-rce': 'php_rce',
        'shellshock': 'shellshock',
        'http-request-smuggling': 'http_request_smuggling',
        'api-abuse': 'api_abuse',
        'credential-stuffing': 'credential_stuffing',
        'jwt-attack': 'jwt_attack',
        'dns-tunneling': 'dns_tunneling',
        'slowloris': 'slowloris',
        'udp-flood': 'udp_flood',
        'icmp-flood': 'icmp_flood',
        'command-injection': 'command_injection',
        'ldap-injection': 'ldap_injection',
        'xxe': 'xxe',
        'ssti': 'ssti',
        'insecure-deserialization': 'insecure_deserialization'
    };

    const typeKey = slugToKey[slug] || slug.replace(/-/g, '_');

    const recentTableBody = document.getElementById('relatedAlertsBody');
    const simButton = document.getElementById('btnRunSimulation');
    const simResultCard = document.getElementById('simResultCard');
    const detectionCountBadge = document.getElementById('attackDetectionCount');

    // ── WebSocket Lifecycle ──────────────────────────────────────
    IDS.createWebSocket(
        (msg) => {
            if (msg.type === 'new_alert' && msg.data) {
                if (msg.data.alert_type === typeKey || msg.data.alert_type === slug) {
                    incrementDetectionBadge();
                    loadRecentAlerts();
                }
            }
        },
        (status) => {
            const dot = document.getElementById('wsDot');
            const lbl = document.getElementById('wsStatus');
            if (!dot || !lbl) return;
            lbl.textContent = status;
            dot.style.background = status === 'CONNECTED' ? '#10b981' : (status === 'RECONNECTING' ? '#f59e0b' : '#ef4444');
            lbl.style.color = dot.style.background;
        }
    );

    function incrementDetectionBadge() {
        if (!detectionCountBadge) return;
        const cur = parseInt(detectionCountBadge.textContent || '0', 10);
        detectionCountBadge.textContent = `${cur + 1} Detections Recorded`;
    }

    // ── Load Stats for Detection Badge ───────────────────────────
    async function loadStats() {
        try {
            const resp = await IDS.apiFetch('/api/stats');
            if (!resp.ok) return;
            const data = await resp.json();
            const counts = data.alerts_by_type || {};
            const count = counts[typeKey] || counts[slug] || 0;
            if (detectionCountBadge) {
                detectionCountBadge.textContent = `${count} Detection${count === 1 ? '' : 's'} Recorded`;
            }
        } catch (e) {
            console.warn('Failed to load attack stats:', e);
        }
    }

    // ── Load Related Incidents ───────────────────────────────────
    async function loadRecentAlerts() {
        if (!recentTableBody) return;
        try {
            const resp = await IDS.apiFetch(`/api/alerts?attack_type=${encodeURIComponent(typeKey)}&limit=10`);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const alerts = await resp.json();

            if (!alerts || alerts.length === 0) {
                recentTableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:#64748b;">No recent incidents recorded in database for this attack vector.</td></tr>`;
                return;
            }

            recentTableBody.innerHTML = alerts.map(a => {
                const actionBadge = a.auto_blocked 
                    ? `<span class="badge badge-high" style="background:#7f1d1d;">BLOCKED</span>` 
                    : `<span class="badge badge-low">ALERTED</span>`;
                return `
                    <tr style="cursor:pointer;" onclick="viewAlertDetail(${a.id})">
                        <td style="font-family:monospace; font-size:0.8rem; color:#94a3b8;">${IDS.formatDate(a.timestamp)}</td>
                        <td><code>${a.source_ip}</code></td>
                        <td><code>${a.dest_port || '—'}</code></td>
                        <td>${a.protocol || 'TCP'}</td>
                        <td><span class="badge badge-${a.severity}">${a.severity.toUpperCase()}</span></td>
                        <td>${actionBadge}</td>
                    </tr>
                `;
            }).join('');
        } catch (e) {
            recentTableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#ef4444;">Failed to load incidents: ${e.message}</td></tr>`;
        }
    }

    // ── Safe Simulation Trigger ──────────────────────────────────
    if (simButton) {
        simButton.addEventListener('click', async () => {
            simButton.disabled = true;
            simButton.innerHTML = `<span class="spinner" style="display:inline-block; width:14px; height:14px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:8px;"></span> Transmitting Synthetic Packets...`;

            if (simResultCard) {
                simResultCard.style.display = 'block';
                simResultCard.innerHTML = `
                    <div style="padding:16px; background:#0f172a; border-radius:8px; border:1px solid #334155; color:#94a3b8;">
                        <p style="margin:0;">⏳ Injecting safe test traffic into pipeline queue. Awaiting IDS detector evaluation...</p>
                    </div>
                `;
            }

            const startTime = new Date();

            try {
                const resp = await IDS.apiFetch('/api/generate-traffic', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mode: 'specific', attack_type: slug })
                });

                if (!resp.ok) throw new Error(`Generator returned HTTP ${resp.status}`);
                const genResult = await resp.json();

                // Wait 600ms for backend queue processing and database persistence
                await new Promise(r => setTimeout(r, 600));

                // Fetch the generated alert
                const alertResp = await IDS.apiFetch(`/api/alerts?attack_type=${encodeURIComponent(typeKey)}&limit=1`);
                let matchedAlert = null;
                if (alertResp.ok) {
                    const alerts = await alertResp.json();
                    if (alerts.length > 0) {
                        matchedAlert = alerts[0];
                    }
                }

                // Check block status if we have a source IP
                let isBlocked = false;
                if (matchedAlert && matchedAlert.source_ip) {
                    try {
                        const bResp = await IDS.apiFetch(`/api/blocked`);
                        if (bResp.ok) {
                            const blocks = await bResp.json();
                            isBlocked = blocks.some(b => b.ip_address === matchedAlert.source_ip && b.is_active);
                        }
                    } catch (be) {
                        console.warn('Block check error:', be);
                    }
                }

                renderSimulationResults(genResult, matchedAlert, isBlocked, startTime);
                loadRecentAlerts();
                loadStats();
                IDS.showToast(`Simulation complete: ${genResult.packets_generated} packets injected.`, 'success');

            } catch (err) {
                if (simResultCard) {
                    simResultCard.innerHTML = `
                        <div style="padding:16px; background:#450a0a; border-radius:8px; border:1px solid #b91c1c; color:#fca5a5;">
                            <strong>Simulation Error:</strong> ${err.message}
                        </div>
                    `;
                }
                IDS.showToast(`Simulation failed: ${err.message}`, 'error');
            } finally {
                simButton.disabled = false;
                simButton.innerHTML = `<span>▶ Run Safe Simulation</span>`;
            }
        });
    }

    function renderSimulationResults(genResult, alert, isBlocked, startTime) {
        if (!simResultCard) return;

        const triggered = alert ? true : false;
        const detectionStatus = triggered
            ? `<span style="color:#10b981; font-weight:700;">TRIGGERED (Alert #${alert.id})</span>`
            : `<span style="color:#f59e0b; font-weight:700;">DID NOT TRIGGER (Threshold not breached)</span>`;

        const severity = alert ? `<span class="badge badge-${alert.severity}">${alert.severity.toUpperCase()}</span>` : 'N/A';
        const fwAction = isBlocked || (alert && alert.auto_blocked)
            ? `<span class="badge badge-high" style="background:#7f1d1d;">BLOCKED & QUARANTINED</span>`
            : `<span class="badge badge-low">LOGGED & MONITORED</span>`;

        simResultCard.innerHTML = `
            <div style="background:#0f172a; border-radius:8px; border:1px solid #1e293b; padding:20px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; border-bottom:1px solid #1e293b; padding-bottom:10px;">
                    <h4 style="margin:0; color:#38bdf8; font-size:1rem;">🧪 Live Simulation Results</h4>
                    <span style="font-size:0.8rem; color:#64748b;">Executed at: ${startTime.toLocaleTimeString()}</span>
                </div>
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:14px;">
                    <div>
                        <div style="font-size:0.75rem; color:#64748b; text-transform:uppercase;">Packets Generated</div>
                        <div style="font-size:1.1rem; font-weight:700; color:#f8fafc; font-family:monospace;">${genResult.packets_generated || 0} pkts</div>
                    </div>
                    <div>
                        <div style="font-size:0.75rem; color:#64748b; text-transform:uppercase;">Packets Processed</div>
                        <div style="font-size:1.1rem; font-weight:700; color:#f8fafc; font-family:monospace;">${genResult.packets_generated || 0} pkts</div>
                    </div>
                    <div>
                        <div style="font-size:0.75rem; color:#64748b; text-transform:uppercase;">Detection Triggered</div>
                        <div>${detectionStatus}</div>
                    </div>
                    <div>
                        <div style="font-size:0.75rem; color:#64748b; text-transform:uppercase;">Severity Assigned</div>
                        <div>${severity}</div>
                    </div>
                    <div>
                        <div style="font-size:0.75rem; color:#64748b; text-transform:uppercase;">Firewall Mitigation</div>
                        <div>${fwAction}</div>
                    </div>
                    <div>
                        <div style="font-size:0.75rem; color:#64748b; text-transform:uppercase;">Offending Source IP</div>
                        <div style="font-family:monospace; color:#cbd5e1;">${alert ? alert.source_ip : '203.0.113.X'}</div>
                    </div>
                    <div>
                        <div style="font-size:0.75rem; color:#64748b; text-transform:uppercase;">Quarantine Status</div>
                        <div style="font-weight:600; color:${isBlocked ? '#ef4444' : '#10b981'};">${isBlocked ? 'ACTIVE BLOCK' : 'WHITELISTED / OPEN'}</div>
                    </div>
                    <div>
                        <div style="font-size:0.75rem; color:#64748b; text-transform:uppercase;">Evaluation Reason</div>
                        <div style="font-size:0.8rem; color:#94a3b8; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${alert ? alert.description : 'No breach detected.'}</div>
                    </div>
                </div>
            </div>
        `;
    }

    // Global alert detail modal helper
    window.viewAlertDetail = async function(alertId) {
        try {
            const resp = await IDS.apiFetch(`/api/alerts?limit=50`);
            if (!resp.ok) return;
            const alerts = await resp.json();
            const a = alerts.find(item => item.id === alertId);
            if (!a) return;

            const modal = document.getElementById('alertModal');
            const title = document.getElementById('modalAlertTitle');
            const body = document.getElementById('modalAlertBody');
            if (!modal || !body) return;

            title.textContent = `Incident Record #${a.id} — ${IDS.formatAttackName(a.alert_type)}`;
            body.innerHTML = `
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px; margin-bottom:12px;">
                    <div><strong>Timestamp:</strong> ${IDS.formatDate(a.timestamp)}</div>
                    <div><strong>Severity:</strong> <span class="badge badge-${a.severity}">${a.severity.toUpperCase()}</span></div>
                    <div><strong>Source IP:</strong> <code>${a.source_ip}</code></div>
                    <div><strong>Target:</strong> <code>${a.dest_ip || '192.168.1.10'}:${a.dest_port || '80'}</code></div>
                    <div><strong>Protocol:</strong> ${a.protocol || 'TCP'}</div>
                    <div><strong>Firewall Status:</strong> ${a.auto_blocked ? 'Automated Quarantine (DROP)' : 'Monitoring (PASS)'}</div>
                </div>
                <div style="margin-top:10px; padding:10px; background:#020617; border-radius:6px; border:1px solid #1e293b;">
                    <strong style="color:#38bdf8;">Detector Rationale:</strong>
                    <p style="margin:4px 0 0 0; color:#cbd5e1;">${a.description}</p>
                </div>
            `;
            modal.style.display = 'flex';
        } catch (e) {
            console.error('Modal error:', e);
        }
    };

    // Initial Load
    loadStats();
    loadRecentAlerts();
});
