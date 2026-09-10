/**
 * static/js/attacks.js — Attack Intelligence Center Client Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    if (!IDS.requireAuth()) return;

    const recentTableBody = document.getElementById('recentAlertsBody');

    // ── WebSocket Lifecycle ──────────────────────────────────────
    IDS.createWebSocket(
        (msg) => {
            if (msg.type === 'new_alert' && msg.data) {
                // Update badge count
                const type = msg.data.alert_type;
                const badge = document.getElementById(`cnt-${type}`);
                if (badge) {
                    const current = parseInt(badge.textContent || '0', 10);
                    badge.textContent = `${current + 1} Detections`;
                }
                loadRecentAlerts();
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

    // ── Load Stats & Counts ──────────────────────────────────────
    async function loadStats() {
        try {
            const resp = await IDS.apiFetch('/api/stats');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            
            const typeCounts = data.alerts_by_type || {};
            for (const [atype, count] of Object.entries(typeCounts)) {
                const badge = document.getElementById(`cnt-${atype}`);
                if (badge) {
                    badge.textContent = `${count} Detection${count === 1 ? '' : 's'}`;
                }
            }
        } catch (e) {
            console.warn('Failed to load attack stats:', e);
        }
    }

    // ── Load Recent Alerts ───────────────────────────────────────
    async function loadRecentAlerts() {
        try {
            const resp = await IDS.apiFetch('/api/alerts?limit=10');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const alerts = await resp.json();

            if (!alerts || alerts.length === 0) {
                recentTableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:#64748b;">No recent alerts recorded.</td></tr>`;
                return;
            }

            recentTableBody.innerHTML = alerts.map(a => {
                const actionBadge = a.auto_blocked 
                    ? `<span class="badge badge-high" style="background:#7f1d1d;">BLOCKED</span>` 
                    : `<span class="badge badge-low">ALERTED</span>`;
                const attackUrl = IDS.getAttackUrl(a.alert_type);
                const attackName = IDS.formatAttackName(a.alert_type);

                return `
                    <tr style="cursor:pointer;" onclick="window.location.href='${attackUrl}'">
                        <td style="font-family:monospace; font-size:0.8rem; color:#94a3b8;">${IDS.formatDate(a.timestamp)}</td>
                        <td><a href="${attackUrl}" style="color:#38bdf8; font-weight:600; text-decoration:none;">${attackName}</a></td>
                        <td><span class="badge badge-${a.severity}">${a.severity.toUpperCase()}</span></td>
                        <td><code>${a.source_ip}</code></td>
                        <td style="color:#cbd5e1; max-width:320px; overflow:hidden; text-overflow:ellipsis;">${a.description}</td>
                        <td>${actionBadge}</td>
                    </tr>
                `;
            }).join('');
        } catch (e) {
            recentTableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#ef4444;">Failed to load alerts: ${e.message}</td></tr>`;
        }
    }

    // Initial load
    loadStats();
    loadRecentAlerts();
});
