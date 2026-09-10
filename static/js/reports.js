/**
 * static/js/reports.js — Security Operations Report Center Client Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    if (!IDS.requireAuth()) return;

    let activePeriod = '24h';

    // DOM references
    const pills = document.querySelectorAll('#reportPeriodPills .quick-pill');
    const btnDownloadHtml = document.getElementById('btnDownloadHtml');
    const btnDownloadCsv = document.getElementById('btnDownloadCsv');
    const btnDownloadJson = document.getElementById('btnDownloadJson');
    const btnPrintPdf = document.getElementById('btnPrintPdf');

    // Report preview fields
    const repId = document.getElementById('repId');
    const repPeriodLabel = document.getElementById('repPeriodLabel');
    const repGeneratedAt = document.getElementById('repGeneratedAt');
    const repOverallStatus = document.getElementById('repOverallStatus');
    const repTotalAlerts = document.getElementById('repTotalAlerts');
    const repAutoBlocked = document.getElementById('repAutoBlocked');
    const repActiveBlocks = document.getElementById('repActiveBlocks');
    const repProcessedPackets = document.getElementById('repProcessedPackets');

    const repSevHigh = document.getElementById('repSevHigh');
    const repSevMed = document.getElementById('repSevMed');
    const repSevLow = document.getElementById('repSevLow');

    const repTopAttackersTable = document.getElementById('repTopAttackersTable');
    const repAlertsTableBody = document.getElementById('repAlertsTableBody');
    const repBlockedTableBody = document.getElementById('repBlockedTableBody');
    const repRecommendationsList = document.getElementById('repRecommendationsList');

    // ── WebSocket Lifecycle ──────────────────────────────────────
    IDS.createWebSocket(
        null,
        (status) => {
            const dot = document.getElementById('wsDot');
            const lbl = document.getElementById('wsStatus');
            if (!dot || !lbl) return;
            lbl.textContent = status;
            dot.style.background = status === 'CONNECTED' ? '#10b981' : (status === 'RECONNECTING' ? '#f59e0b' : '#ef4444');
            lbl.style.color = dot.style.background;
        }
    );

    // ── Fetch Report Preview Data ────────────────────────────────
    async function loadReportPreview() {
        try {
            const resp = await IDS.apiFetch(`/api/report/data?period=${activePeriod}`);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            renderPreview(data);
        } catch (err) {
            console.error('Failed to load report preview:', err);
            IDS.showToast(`Failed to generate report preview: ${err.message}`, 'error');
        }
    }

    // ── Render Preview ───────────────────────────────────────────
    function renderPreview(data) {
        repId.textContent = data.report_id;
        repPeriodLabel.textContent = data.period_label;
        repGeneratedAt.textContent = data.generated_at;

        const summary = data.executive_summary;
        repOverallStatus.textContent = summary.overall_status;
        repOverallStatus.className = `badge ${summary.overall_status === 'CRITICAL THREATS' ? 'badge-high' : (summary.overall_status === 'ELEVATED' ? 'badge-medium' : 'badge-low')}`;

        repTotalAlerts.textContent = summary.total_alerts;
        repAutoBlocked.textContent = summary.auto_blocked_count;
        repActiveBlocks.textContent = summary.active_blocks_count;
        repProcessedPackets.textContent = summary.packets_processed;

        repSevHigh.textContent = data.severity_analysis.high || 0;
        repSevMed.textContent = data.severity_analysis.medium || 0;
        repSevLow.textContent = data.severity_analysis.low || 0;

        // Top Attackers
        if (data.top_attackers && data.top_attackers.length > 0) {
            repTopAttackersTable.innerHTML = data.top_attackers.map(atk => `
                <tr>
                    <td style="padding:6px 0;"><code style="color:#38bdf8;">${atk.ip}</code></td>
                    <td style="text-align:right; font-weight:700; color:#f8fafc;">${atk.count} alerts</td>
                </tr>
            `).join('');
        } else {
            repTopAttackersTable.innerHTML = `<tr><td colspan="2" style="color:#64748b; text-align:center; padding:15px;">No attack incidents for this period.</td></tr>`;
        }

        // Alerts Table
        if (data.recent_alerts && data.recent_alerts.length > 0) {
            repAlertsTableBody.innerHTML = data.recent_alerts.map(a => {
                const actionBadge = a.auto_blocked 
                    ? `<span class="badge badge-high" style="background:#7f1d1d;">BLOCKED</span>` 
                    : `<span class="badge badge-low">ALERTED</span>`;
                return `
                    <tr>
                        <td style="font-family:monospace; font-size:0.8rem; color:#94a3b8;">${a.timestamp}</td>
                        <td><code style="color:#38bdf8;">${a.source_ip}</code></td>
                        <td>${IDS.formatAttackName(a.alert_type)}</td>
                        <td><span class="badge badge-${a.severity}">${a.severity.toUpperCase()}</span></td>
                        <td>${actionBadge}</td>
                        <td style="color:#cbd5e1; max-width:300px; overflow:hidden; text-overflow:ellipsis;">${a.description}</td>
                    </tr>
                `;
            }).join('');
        } else {
            repAlertsTableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#64748b; padding:25px;">No security alerts recorded for this period.</td></tr>`;
        }

        // Blocked Table
        if (data.blocked_ips && data.blocked_ips.length > 0) {
            repBlockedTableBody.innerHTML = data.blocked_ips.map(b => `
                <tr>
                    <td><code style="color:#f43f5e; font-weight:700;">${b.ip_address}</code></td>
                    <td>${b.reason}</td>
                    <td style="font-family:monospace; font-size:0.8rem; color:#94a3b8;">${b.blocked_at}</td>
                    <td style="font-family:monospace; font-size:0.8rem; color:#94a3b8;">${b.expires_at}</td>
                </tr>
            `).join('');
        } else {
            repBlockedTableBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#64748b; padding:20px;">No active quarantined hosts for this period.</td></tr>`;
        }

        // Recommendations
        if (data.recommendations && data.recommendations.length > 0) {
            repRecommendationsList.innerHTML = data.recommendations.map(r => `
                <li style="margin-bottom:8px; color:#e2e8f0;">${r}</li>
            `).join('');
        }
    }

    // ── Period Switching ─────────────────────────────────────────
    pills.forEach(pill => {
        pill.addEventListener('click', () => {
            pills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            activePeriod = pill.dataset.period;
            loadReportPreview();
        });
    });

    // ── Export Actions ───────────────────────────────────────────
    btnDownloadHtml.addEventListener('click', () => {
        window.open(`/api/report/html?period=${activePeriod}`, '_blank');
        IDS.showToast('Generating standalone HTML report...', 'info');
    });

    btnDownloadCsv.addEventListener('click', () => {
        window.open(`/api/report/csv?period=${activePeriod}`, '_blank');
        IDS.showToast('Downloading Alerts CSV spreadsheet...', 'info');
    });

    btnDownloadJson.addEventListener('click', () => {
        window.open(`/api/report/json?period=${activePeriod}`, '_blank');
        IDS.showToast('Downloading Security JSON raw data...', 'info');
    });

    btnPrintPdf.addEventListener('click', () => {
        window.print();
    });

    // Initial load
    loadReportPreview();
});
