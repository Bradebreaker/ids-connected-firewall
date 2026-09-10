/**
 * static/js/app.js — SOC Command Center Dashboard Client Logic
 *
 * Implements:
 *   - Real backend state synchronization for Refresh (metrics, alerts, blocks, firewall, system health)
 *   - Auto-refresh toggle (15s, 30s, 60s, Off)
 *   - Interactive drill-downs for KPI cards (/alerts.html?filter=all, ?filter=today, /blocked-ips.html?filter=active, /alerts.html?source=...)
 *   - Real-time WebSocket event ingestion (alerts + packet streams)
 *   - Dynamic multi-category chart visualization (24h timeline, severity donut, dynamic attack bar chart)
 *   - Synthetic traffic generator for all 23 attack vectors
 *   - Alert investigation modal with direct deep-dive links to /attacks/<slug>.html
 */

(function () {
    'use strict';

    if (!IDS.requireAuth()) return;

    // ── DOM References ──────────────────────────────────────────
    const alertFeed       = document.getElementById('alertFeed');
    const alertCountLabel = document.getElementById('alertCountLabel');
    const wsDot           = document.getElementById('wsDot');
    const wsStatus        = document.getElementById('wsStatus');
    const threatIndicator = document.getElementById('threatIndicator');
    const threatText      = document.getElementById('threatText');

    // Stats KPIs
    const statTotal    = document.getElementById('statTotalAlerts');
    const statToday    = document.getElementById('statTodayAlerts');
    const statBlocks   = document.getElementById('statActiveBlocks');
    const statAttacker = document.getElementById('statTopAttacker');

    // Refresh & Status
    const refreshBtn       = document.getElementById('refreshBtn');
    const refreshBtnText   = document.getElementById('refreshBtnText');
    const refreshBtnIcon   = document.getElementById('refreshBtnIcon');
    const lastUpdatedLabel = document.getElementById('lastUpdated');

    // Traffic stream
    const trafficFeed       = document.getElementById('trafficFeed');
    const trafficCountLabel = document.getElementById('trafficCountLabel');
    const pauseBtn          = document.getElementById('pauseStreamBtn');
    const clearBtn          = document.getElementById('clearStreamBtn');

    // ── State ───────────────────────────────────────────────────
    let wsController = null;
    let alertsInFeed = 0;
    let trafficInFeed = 0;
    let trafficPaused = false;
    const dataCache = {};

    let attackChart = null;
    let severityChart = null;
    let typeChart = null;

    let autoRefreshTimer = null;

    // ── Auto-Refresh Handler ────────────────────────────────────
    window.toggleAutoRefresh = function(secondsStr) {
        if (autoRefreshTimer) {
            clearInterval(autoRefreshTimer);
            autoRefreshTimer = null;
        }
        const secs = parseInt(secondsStr, 10);
        if (secs > 0) {
            autoRefreshTimer = setInterval(() => {
                refreshDashboard(true);
            }, secs * 1000);
            IDS.showToast(`Auto-refresh enabled (${secs}s interval)`, 'info');
        } else {
            IDS.showToast('Auto-refresh paused', 'info');
        }
    };

    // ── Top Attacker Drilldown ──────────────────────────────────
    window.drilldownTopAttacker = function() {
        if (!statAttacker) {
            window.location.href = '/alerts.html';
            return;
        }
        const ip = statAttacker.textContent.trim();
        if (ip && ip !== '—' && ip !== 'None' && ip !== '') {
            window.location.href = `/alerts.html?source=${encodeURIComponent(ip)}`;
        } else {
            window.location.href = '/alerts.html';
        }
    };

    // ── Details Modal ───────────────────────────────────────────
    window.showDetailsModal = function(id) {
        const data = dataCache[id];
        if (!data) return;

        const modal = document.getElementById('detailsModal');
        if (!modal) return;

        const isAlert = !!data.alert_type;
        document.getElementById('modalTitle').textContent = isAlert ? 'Incident Details' : 'Packet Details';
        document.getElementById('modalSourceIp').textContent = data.source_ip || 'N/A';
        document.getElementById('modalDestIp').textContent = data.dest_ip || '192.168.1.10';
        document.getElementById('modalDestPort').textContent = data.dest_port || '—';
        document.getElementById('modalProtocol').textContent = data.protocol || 'TCP';
        document.getElementById('modalAlertType').textContent = isAlert ? IDS.formatAttackName(data.alert_type) : 'Normal Frame';
        document.getElementById('modalSeverity').textContent = isAlert ? data.severity.toUpperCase() : 'INFO';

        document.getElementById('modalTime').textContent = IDS.formatDate(data.timestamp);
        document.getElementById('modalDescription').textContent = data.description || data.threat_detail || 'No anomaly flagged';

        const blocked = document.getElementById('modalBlocked');
        if (blocked) {
            if (isAlert) {
                blocked.textContent = data.auto_blocked ? 'YES — Offending IP Quarantined' : 'NO — Monitored';
                blocked.style.color = data.auto_blocked ? '#ef4444' : '#22c55e';
            } else {
                blocked.textContent = 'N/A (Normal Traffic)';
                blocked.style.color = '#94a3b8';
            }
        }

        const payloadEl = document.getElementById('modalPayload');
        let rawPayload = data.payload || data.raw_packet || '';
        payloadEl.textContent = rawPayload || '<No application payload>';

        const intelLink = document.getElementById('modalAttackIntelLink');
        if (intelLink) {
            if (isAlert) {
                intelLink.style.display = 'inline-block';
                intelLink.href = IDS.getAttackUrl(data.alert_type);
                intelLink.textContent = `⚔️ View ${IDS.formatAttackName(data.alert_type)} Intel →`;
            } else {
                intelLink.style.display = 'none';
            }
        }

        modal.style.display = 'flex';
    };

    window.closeDetailsModal = function() {
        const modal = document.getElementById('detailsModal');
        if (modal) modal.style.display = 'none';
    };

    document.addEventListener('click', (e) => {
        const modal = document.getElementById('detailsModal');
        if (e.target === modal) closeDetailsModal();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeDetailsModal();
    });

    // ── Live Alert Feed Rendering ───────────────────────────────
    function addAlertToFeed(alert, isRealtime = false) {
        if (!alertFeed) return;
        const emptyState = alertFeed.querySelector('.empty-state');
        if (emptyState) emptyState.remove();

        const alertId = alert.id || 'alt_' + Math.random().toString(36).substring(7);
        dataCache[alertId] = alert;

        const item = document.createElement('div');
        item.className = `alert-item severity-${alert.severity} ${isRealtime ? 'new-row' : ''}`;
        item.onclick = () => showDetailsModal(alertId);
        item.style.cursor = 'pointer';

        const attackName = IDS.formatAttackName(alert.alert_type);
        const attackUrl = IDS.getAttackUrl(alert.alert_type);

        item.innerHTML = `
            <span class="alert-severity-badge badge-${alert.severity}">
                ${alert.severity.toUpperCase()}
            </span>
            <div class="alert-content">
                <div class="alert-title" style="display:flex; justify-content:space-between; align-items:center;">
                    <a href="${attackUrl}" onclick="event.stopPropagation()" style="color:#38bdf8; text-decoration:none; font-weight:600;">
                        ${attackName}
                    </a>
                    ${alert.auto_blocked ? '<span class="alert-blocked-badge">AUTO-BLOCKED</span>' : ''}
                </div>
                <div class="alert-meta">
                    <span>📍 <code>${alert.source_ip}</code></span>
                    ${alert.dest_port ? `<span>🔌 Port ${alert.dest_port}</span>` : ''}
                    ${alert.protocol ? `<span>📡 ${alert.protocol}</span>` : ''}
                    <span>🕐 ${IDS.formatDate(alert.timestamp)}</span>
                </div>
                <div class="alert-desc">${alert.description || ''}</div>
            </div>
        `;

        alertFeed.insertBefore(item, alertFeed.firstChild);
        alertsInFeed++;

        if (alertsInFeed > 80) {
            alertFeed.removeChild(alertFeed.lastChild);
            alertsInFeed--;
        }
        if (alertCountLabel) alertCountLabel.textContent = `${alertsInFeed} alerts recorded →`;
    }

    // ── Live Packet Stream ──────────────────────────────────────
    function handleTrafficEvent(packet) {
        if (trafficPaused) return;
        if (!trafficFeed) return;

        const item = document.createElement('div');
        const pktId = 'pkt_' + Math.random().toString(36).substring(7);
        dataCache[pktId] = packet;

        item.className = 'traffic-row';
        item.onclick = () => showDetailsModal(pktId);
        item.style.cursor = 'pointer';

        let timeStr = new Date().toLocaleTimeString();
        if (packet.timestamp) {
            const d = new Date(packet.timestamp);
            if (!isNaN(d.getTime())) timeStr = d.toLocaleTimeString();
        }

        const proto = packet.protocol || 'TCP';
        const flags = packet.tcp_flags || '—';
        const size  = packet.packet_length || (packet.payload ? packet.payload.length : 0);
        const srcPort = packet.source_port ? `:${packet.source_port}` : '';
        const dstPort = packet.dest_port ? `:${packet.dest_port}` : '';

        item.innerHTML = `
            <span class="pkt-time">${timeStr}</span>
            <span class="pkt-src"><code>${packet.source_ip || '—'}${srcPort}</code></span>
            <span class="pkt-arrow">→</span>
            <span class="pkt-dst"><code>${packet.dest_ip || '192.168.1.10'}${dstPort}</code></span>
            <span class="pkt-proto"><span class="badge badge-proto">${proto}</span></span>
            <span class="pkt-flags">${flags}</span>
            <span class="pkt-size">${size}B</span>
        `;

        trafficFeed.insertBefore(item, trafficFeed.firstChild);
        trafficInFeed++;

        if (trafficInFeed > 60) {
            trafficFeed.removeChild(trafficFeed.lastChild);
            trafficInFeed--;
        }
        if (trafficCountLabel) trafficCountLabel.textContent = `${trafficInFeed} packets`;
    }

    window.togglePause = function() {
        trafficPaused = !trafficPaused;
        if (pauseBtn) {
            pauseBtn.textContent = trafficPaused ? '▶ Resume' : '⏸ Pause';
            pauseBtn.classList.toggle('paused', trafficPaused);
        }
    };

    window.clearStream = function() {
        if (trafficFeed) trafficFeed.innerHTML = '';
        trafficInFeed = 0;
        if (trafficCountLabel) trafficCountLabel.textContent = '0 packets';
    };

    // ── Load Recent Alerts ──────────────────────────────────────
    async function loadRecentAlerts() {
        try {
            const res = await IDS.apiFetch('/api/alerts?limit=25');
            if (!res.ok) return;
            const alerts = await res.json();
            if (alertFeed) alertFeed.innerHTML = '';
            alertsInFeed = 0;

            alerts.reverse().forEach(a => {
                addAlertToFeed(a, false);
            });
        } catch (e) {
            console.error('Failed to load alerts:', e);
        }
    }

    // ── Stats Fetching & Chart Rendering ────────────────────────
    async function fetchStats() {
        try {
            const res = await IDS.apiFetch('/api/stats');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const stats = await res.json();
            renderStats(stats);
        } catch (e) {
            console.error('Failed to fetch stats:', e);
            throw e;
        }
    }

    function renderStats(s) {
        if (statTotal)    statTotal.textContent    = (s.total_alerts || 0).toLocaleString();
        if (statToday)    statToday.textContent    = (s.alerts_today || 0).toLocaleString();
        if (statBlocks)   statBlocks.textContent   = (s.active_blocks || 0).toLocaleString();
        if (statAttacker) statAttacker.textContent = s.top_attacker || 'None Observed';

        updateThreatLevel(s.threat_level || 'low');
        updateAttackChart(s.alerts_per_hour || []);
        updateSeverityChart(s.alerts_by_severity || {});
        updateTypeChart(s.alerts_by_type || {});
    }

    function updateThreatLevel(level) {
        if (threatIndicator) {
            threatIndicator.className = `threat-indicator level-${level.toLowerCase()}`;
        }
        if (threatText) {
            threatText.textContent = level.toUpperCase();
        }
    }

    // ── Charts Implementation ───────────────────────────────────
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(148,163,184,0.08)';
    Chart.defaults.font.family = "'Inter', sans-serif";

    function updateAttackChart(alertsPerHour) {
        const labels = alertsPerHour.map(a => {
            const d = new Date(a.hour);
            return isNaN(d.getTime()) ? String(a.hour) : d.getHours().toString().padStart(2, '0') + ':00';
        });
        const data = alertsPerHour.map(a => a.count);
        const ctx = document.getElementById('attackChart');
        if (!ctx) return;

        if (attackChart) {
            attackChart.data.labels = labels;
            attackChart.data.datasets[0].data = data;
            attackChart.update('none');
            return;
        }

        attackChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Alerts',
                    data,
                    borderColor: '#22d3ee',
                    backgroundColor: 'rgba(34,211,238,0.08)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 3,
                    pointBackgroundColor: '#22d3ee',
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: { backgroundColor: '#0f172a', borderColor: 'rgba(34,211,238,0.4)', borderWidth: 1 }
                },
                scales: {
                    x: { grid: { display: false }, ticks: { maxTicksLimit: 12, font: { size: 11 } } },
                    y: { beginAtZero: true, grid: { color: 'rgba(148,163,184,0.06)' }, ticks: { font: { size: 11 }, precision: 0 } },
                },
            },
        });
    }

    function updateSeverityChart(bySeverity) {
        const labels = ['Low', 'Medium', 'High', 'Critical'];
        const data   = [
            bySeverity.low || 0,
            bySeverity.medium || 0,
            bySeverity.high || 0,
            bySeverity.critical || 0
        ];
        const colors = ['#22d3ee', '#f59e0b', '#ef4444', '#dc2626'];
        const ctx = document.getElementById('severityChart');
        if (!ctx) return;

        if (severityChart) {
            severityChart.data.datasets[0].data = data;
            severityChart.update('none');
            return;
        }
        severityChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{ data, backgroundColor: colors, borderColor: '#0f172a', borderWidth: 2 }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: { position: 'bottom', labels: { padding: 14, usePointStyle: true, pointStyleWidth: 8 } }
                }
            },
        });
    }

    function updateTypeChart(byType) {
        // Sort categories by count descending
        const entries = Object.entries(byType).sort((a, b) => b[1] - a[1]).slice(0, 6);
        const labels = entries.length > 0 ? entries.map(e => IDS.formatAttackName(e[0])) : ['Port Scan', 'SQLi', 'Brute Force'];
        const data = entries.length > 0 ? entries.map(e => e[1]) : [0, 0, 0];
        const colors = ['#38bdf8', '#818cf8', '#f59e0b', '#ef4444', '#10b981', '#a855f7'];

        const ctx = document.getElementById('typeChart');
        if (!ctx) return;

        if (typeChart) {
            typeChart.data.labels = labels;
            typeChart.data.datasets[0].data = data;
            typeChart.update('none');
            return;
        }

        typeChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    data,
                    backgroundColor: colors.map(c => c + '33'),
                    borderColor: colors,
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, grid: { color: 'rgba(148,163,184,0.06)' }, ticks: { font: { size: 11 }, precision: 0 } },
                    y: { grid: { display: false }, ticks: { font: { size: 11 } } },
                },
            },
        });
    }

    // ── Real Synchronization Refresh ────────────────────────────
    window.refreshDashboard = async function(isSilent = false) {
        if (refreshBtn && !isSilent) {
            refreshBtn.disabled = true;
            if (refreshBtnText) refreshBtnText.textContent = 'Refreshing...';
            if (refreshBtnIcon) refreshBtnIcon.textContent = '⏳';
            refreshBtn.classList.add('spinning');
        }

        try {
            // Concurrently query live backend subsystems
            const [statsRes, alertsRes, sysRes] = await Promise.all([
                IDS.apiFetch('/api/stats'),
                IDS.apiFetch('/api/alerts?limit=25'),
                IDS.apiFetch('/api/system/status')
            ]);

            if (!statsRes.ok) throw new Error('Stats synchronization failed');
            const stats = await statsRes.json();
            renderStats(stats);

            if (alertsRes.ok) {
                const alerts = await alertsRes.json();
                if (alertFeed) alertFeed.innerHTML = '';
                alertsInFeed = 0;
                alerts.reverse().forEach(a => addAlertToFeed(a, false));
            }

            if (lastUpdatedLabel) {
                lastUpdatedLabel.textContent = 'Last updated: ' + new Date().toLocaleTimeString();
            }

            if (refreshBtnText && !isSilent) refreshBtnText.textContent = 'Refresh';
            if (refreshBtnIcon && !isSilent) refreshBtnIcon.textContent = '🔄';
            if (!isSilent) IDS.showToast('SOC state synchronized with server', 'success');

        } catch (e) {
            console.error('Refresh synchronization failed:', e);
            if (refreshBtnText) refreshBtnText.textContent = 'Refresh failed — Retry';
            if (refreshBtnIcon) refreshBtnIcon.textContent = '⚠️';
            if (!isSilent) IDS.showToast('Refresh failed. Check server status.', 'error');
        } finally {
            if (refreshBtn) {
                refreshBtn.disabled = false;
                refreshBtn.classList.remove('spinning');
            }
        }
    };

    // ── Synthetic Traffic Generator ─────────────────────────────
    window.generateTraffic = async function(mode) {
        const out = document.getElementById('generatorOutput');
        if (out) out.textContent = `[${new Date().toLocaleTimeString()}] Injecting ${mode} synthetic stream into packet queue...`;

        try {
            const res = await IDS.apiFetch('/api/generate-traffic', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: mode, attack_type: null })
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            if (out) out.textContent = `[${new Date().toLocaleTimeString()}] ✅ Dispatched ${data.packets_generated} packets (${data.attack_type || mode})`;
            IDS.showToast(`Injected ${data.packets_generated} packets (${mode})`, 'success');
        } catch (e) {
            if (out) out.textContent = `[${new Date().toLocaleTimeString()}] ❌ Failed: ${e.message}`;
            IDS.showToast(`Generation failed: ${e.message}`, 'error');
        }
    };

    window.generateSpecificTraffic = async function() {
        const select = document.getElementById('attackTypeSelect');
        const attackType = select ? select.value : 'port_scan';
        const out = document.getElementById('generatorOutput');
        if (out) out.textContent = `[${new Date().toLocaleTimeString()}] Injecting ${IDS.formatAttackName(attackType)} into detection pipeline...`;

        try {
            const res = await IDS.apiFetch('/api/generate-traffic', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: 'specific', attack_type: attackType })
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            if (out) out.textContent = `[${new Date().toLocaleTimeString()}] ✅ Injected ${data.packets_generated} packets for ${data.attack_type}`;
            IDS.showToast(`Injected vector: ${IDS.formatAttackName(attackType)} (${data.packets_generated} pkts)`, 'success');
        } catch (e) {
            if (out) out.textContent = `[${new Date().toLocaleTimeString()}] ❌ Failed: ${e.message}`;
            IDS.showToast(`Failed: ${e.message}`, 'error');
        }
    };

    // ── WebSocket Lifecycle ──────────────────────────────────────
    function initWebSocket() {
        wsController = IDS.createWebSocket(
            (msg) => {
                if (msg.type === 'new_alert' && msg.data) {
                    addAlertToFeed(msg.data, true);
                    // Increment total count locally
                    if (statTotal) {
                        const cur = parseInt(statTotal.textContent.replace(/,/g, '') || '0', 10);
                        statTotal.textContent = (cur + 1).toLocaleString();
                    }
                } else if (msg.type === 'packet' && msg.data) {
                    handleTrafficEvent(msg.data);
                } else if (msg.type === 'ip_blocked' && msg.data) {
                    if (statBlocks) {
                        const cur = parseInt(statBlocks.textContent.replace(/,/g, '') || '0', 10);
                        statBlocks.textContent = (cur + 1).toLocaleString();
                    }
                    IDS.showToast(`Host quarantined: ${msg.data.ip_address || msg.data.ip}`, 'warning');
                } else if (msg.type === 'system_reset') {
                    clearStream();
                    refreshDashboard(true);
                    IDS.showToast('Demonstration data was reset. Dashboard synchronized.', 'info');
                }
            },
            (status) => {
                if (!wsDot || !wsStatus) return;
                wsStatus.textContent = status;
                if (status === 'CONNECTED') {
                    wsDot.className = 'connection-dot connected';
                } else if (status === 'CONNECTING' || status === 'RECONNECTING') {
                    wsDot.className = 'connection-dot connecting';
                } else {
                    wsDot.className = 'connection-dot disconnected';
                }
            }
        );
    }

    // ── Database / System Reset Modal Handlers ──────────────────
    const resetModalBackdrop = document.getElementById('resetDbModalBackdrop');
    const resetConfirmInput  = document.getElementById('resetConfirmInput');
    const btnConfirmDbReset  = document.getElementById('btnConfirmDbReset');
    const btnCancelDbReset   = document.getElementById('btnCancelDbReset');
    const btnResetSpinner    = document.getElementById('btnResetSpinner');
    const btnResetText       = document.getElementById('btnResetText');
    const resetFeedback      = document.getElementById('resetFeedback');

    let resetInProgress = false;

    window.openResetDatabaseModal = function() {
        if (!resetModalBackdrop) return;
        resetModalBackdrop.style.display = 'flex';
        if (resetConfirmInput) {
            resetConfirmInput.value = '';
            setTimeout(() => resetConfirmInput.focus(), 60);
        }
        if (btnConfirmDbReset) {
            btnConfirmDbReset.disabled = true;
            btnConfirmDbReset.style.opacity = '0.4';
            btnConfirmDbReset.style.cursor = 'not-allowed';
        }
        if (btnCancelDbReset) btnCancelDbReset.disabled = false;
        if (btnResetSpinner) btnResetSpinner.style.display = 'none';
        if (btnResetText) btnResetText.textContent = 'Confirm Reset';
        if (resetFeedback) {
            resetFeedback.style.display = 'none';
            resetFeedback.textContent = '';
        }
    };

    window.closeResetDatabaseModal = function() {
        if (resetInProgress) return;
        if (resetModalBackdrop) {
            resetModalBackdrop.style.display = 'none';
        }
    };

    window.validateResetInput = function(val) {
        if (!btnConfirmDbReset) return;
        if (val && val.trim().toUpperCase() === 'RESET') {
            btnConfirmDbReset.disabled = false;
            btnConfirmDbReset.style.opacity = '1';
            btnConfirmDbReset.style.cursor = 'pointer';
        } else {
            btnConfirmDbReset.disabled = true;
            btnConfirmDbReset.style.opacity = '0.4';
            btnConfirmDbReset.style.cursor = 'not-allowed';
        }
    };

    window.executeDatabaseReset = async function() {
        if (resetInProgress) return;
        resetInProgress = true;

        if (btnConfirmDbReset) btnConfirmDbReset.disabled = true;
        if (btnCancelDbReset) btnCancelDbReset.disabled = true;
        if (btnResetSpinner) btnResetSpinner.style.display = 'inline-block';
        if (btnResetText) btnResetText.textContent = 'Compacting database...';

        if (resetFeedback) {
            resetFeedback.style.display = 'block';
            resetFeedback.style.background = 'rgba(56, 189, 248, 0.1)';
            resetFeedback.style.color = '#38bdf8';
            resetFeedback.style.border = '1px solid rgba(56, 189, 248, 0.3)';
            resetFeedback.textContent = 'Purging demonstration records and vacuuming SQLite storage...';
        }

        try {
            const res = await IDS.apiFetch('/api/system/reset-data', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || `Server error (HTTP ${res.status})`);
            }

            const data = await res.json();

            // Clear live stream in-memory items
            clearStream();

            // Refresh dashboard immediately
            await refreshDashboard(true);

            // Close modal
            resetInProgress = false;
            if (resetModalBackdrop) resetModalBackdrop.style.display = 'none';

            IDS.showToast(
                `Reset complete: Purged ${data.alerts_deleted} alerts, ${data.temporary_blocks_deleted} temporary blocks. Storage: ${data.database_size_before_kb} KB → ${data.database_size_after_kb} KB.`,
                'success'
            );
        } catch (e) {
            resetInProgress = false;
            if (btnConfirmDbReset) btnConfirmDbReset.disabled = false;
            if (btnCancelDbReset) btnCancelDbReset.disabled = false;
            if (btnResetSpinner) btnResetSpinner.style.display = 'none';
            if (btnResetText) btnResetText.textContent = 'Confirm Reset';

            if (resetFeedback) {
                resetFeedback.style.display = 'block';
                resetFeedback.style.background = 'rgba(239, 68, 68, 0.1)';
                resetFeedback.style.color = '#fca5a5';
                resetFeedback.style.border = '1px solid rgba(239, 68, 68, 0.3)';
                resetFeedback.textContent = `Reset failed: ${e.message}`;
            }
            IDS.showToast(`Reset error: ${e.message}`, 'error');
        }
    };

    // ── Initialisation ──────────────────────────────────────────
    (async function init() {
        await refreshDashboard(true);
        initWebSocket();
        // Start default 30s auto-refresh
        toggleAutoRefresh('30');
    })();

})();

