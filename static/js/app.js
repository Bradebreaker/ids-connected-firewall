/**
 * app.js — Main dashboard logic.
 *
 * Handles:
 *   - JWT auth guard (redirect to login if not authenticated)
 *   - WebSocket connection for live alert streaming
 *   - Stats fetching and rendering
 *   - Chart.js charts for attacks-over-time, severity, and type breakdowns
 *   - Live alert feed with slide-in animations
 *   - Threat level indicator updates
 */

(function () {
    'use strict';

    // ── Auth guard ──────────────────────────────────────────────
    const token = localStorage.getItem('ids_token');
    if (!token) {
        window.location.href = '/login';
        return;
    }

    const API_BASE = '';
    const MAX_FEED_ALERTS = 50;

    // ── DOM references ──────────────────────────────────────────
    const alertFeed       = document.getElementById('alertFeed');
    const alertCountLabel = document.getElementById('alertCountLabel');
    const wsDot           = document.getElementById('wsDot');
    const wsStatus        = document.getElementById('wsStatus');
    const threatIndicator = document.getElementById('threatIndicator');
    const threatText      = document.getElementById('threatText');

    // Stats
    const statTotal    = document.getElementById('statTotalAlerts');
    const statToday    = document.getElementById('statTodayAlerts');
    const statBlocks   = document.getElementById('statActiveBlocks');
    const statAttacker = document.getElementById('statTopAttacker');
    const blockedCount = document.getElementById('blockedCount');

    // ── Utility functions ───────────────────────────────────────
    function authHeaders() {
        return { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' };
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    function timeAgo(isoStr) {
        const diff = (Date.now() - new Date(isoStr).getTime()) / 1000;
        if (diff < 60)   return Math.floor(diff) + 's ago';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return new Date(isoStr).toLocaleDateString();
    }

    // ── Global helpers (called from HTML) ───────────────────────
    window.logout = function () {
        localStorage.removeItem('ids_token');
        window.location.href = '/login';
    };

    window.toggleSidebar = function () {
        document.getElementById('sidebar').classList.toggle('mobile-open');
    };


    // ══════════════════════════════════════════════════════════════
    //  WebSocket Connection
    // ══════════════════════════════════════════════════════════════

    let ws = null;
    let wsReconnectTimer = null;
    let alertsInFeed = 0;

    function connectWebSocket() {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${location.host}/ws/alerts?token=${token}`;

        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            wsDot.classList.add('connected');
            wsStatus.textContent = 'Live';
            console.log('WebSocket connected');
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                handleWSMessage(msg);
            } catch (e) {
                console.warn('WS parse error:', e);
            }
        };

        ws.onclose = () => {
            wsDot.classList.remove('connected');
            wsStatus.textContent = 'Disconnected';
            console.log('WebSocket closed, reconnecting in 5s…');
            wsReconnectTimer = setTimeout(connectWebSocket, 5000);
        };

        ws.onerror = (err) => {
            console.error('WebSocket error:', err);
            ws.close();
        };

        // Keep-alive ping every 30s
        setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send('ping');
            }
        }, 30000);
    }

    function handleWSMessage(msg) {
        switch (msg.type) {
            case 'new_alert':
                addAlertToFeed(msg.data);
                // Refresh stats
                fetchStats();
                break;
            case 'ip_blocked':
                console.log('IP blocked:', msg.data);
                fetchStats();
                break;
            case 'ip_unblocked':
                console.log('IP unblocked:', msg.data);
                fetchStats();
                break;
            case 'pong':
                break;
            default:
                console.log('Unknown WS message:', msg);
        }
    }


    // ══════════════════════════════════════════════════════════════
    //  Alert Feed
    // ══════════════════════════════════════════════════════════════

    function addAlertToFeed(alert) {
        // Remove empty state if present
        const emptyState = alertFeed.querySelector('.empty-state');
        if (emptyState) emptyState.remove();

        const item = document.createElement('div');
        item.className = `alert-item severity-${alert.severity}`;
        item.innerHTML = `
            <span class="alert-severity-badge badge-${alert.severity}">
                ${alert.severity.toUpperCase()}
            </span>
            <div class="alert-content">
                <div class="alert-title">
                    ${getAlertTypeLabel(alert.alert_type)}
                    ${alert.auto_blocked ? '<span class="alert-blocked-badge">AUTO-BLOCKED</span>' : ''}
                </div>
                <div class="alert-meta">
                    <span>📍 ${escapeHtml(alert.source_ip)}</span>
                    ${alert.dest_port ? `<span>🔌 Port ${alert.dest_port}</span>` : ''}
                    ${alert.protocol ? `<span>📡 ${alert.protocol}</span>` : ''}
                    <span>🕐 ${timeAgo(alert.timestamp)}</span>
                </div>
                <div class="alert-desc">${escapeHtml(alert.description).substring(0, 150)}</div>
            </div>
        `;

        // Insert at top (newest first)
        alertFeed.insertBefore(item, alertFeed.firstChild);
        alertsInFeed++;

        // Trim old alerts
        while (alertFeed.children.length > MAX_FEED_ALERTS) {
            alertFeed.removeChild(alertFeed.lastChild);
        }

        alertCountLabel.textContent = `${alertsInFeed} alerts`;
    }

    function getAlertTypeLabel(type) {
        const labels = {
            'signature':   '🔏 Signature Match',
            'port_scan':   '🔍 Port Scan',
            'brute_force': '🔑 Brute Force',
            'syn_flood':   '🌊 SYN Flood',
        };
        return labels[type] || type;
    }


    // ══════════════════════════════════════════════════════════════
    //  Load initial alerts
    // ══════════════════════════════════════════════════════════════

    async function loadRecentAlerts() {
        try {
            const res = await fetch(API_BASE + '/api/alerts?limit=30', { headers: authHeaders() });
            if (res.status === 401) { window.logout(); return; }
            const alerts = await res.json();
            // Add in reverse order (oldest first) so newest is on top
            alerts.reverse().forEach(a => addAlertToFeed(a));
        } catch (e) {
            console.error('Failed to load alerts:', e);
        }
    }


    // ══════════════════════════════════════════════════════════════
    //  Stats
    // ══════════════════════════════════════════════════════════════

    let attackChart = null;
    let severityChart = null;
    let typeChart = null;

    async function fetchStats() {
        try {
            const res = await fetch(API_BASE + '/api/stats', { headers: authHeaders() });
            if (res.status === 401) { window.logout(); return; }
            const stats = await res.json();
            renderStats(stats);
        } catch (e) {
            console.error('Failed to load stats:', e);
        }
    }

    function renderStats(s) {
        // Cards
        statTotal.textContent    = s.total_alerts.toLocaleString();
        statToday.textContent    = s.alerts_today.toLocaleString();
        statBlocks.textContent   = s.active_blocks.toLocaleString();
        statAttacker.textContent = s.top_attacker || '—';

        if (blockedCount && s.active_blocks > 0) {
            blockedCount.textContent = s.active_blocks;
            blockedCount.style.display = 'inline-block';
        }

        // Threat level indicator
        updateThreatLevel(s.threat_level);

        // Charts
        updateAttackChart(s.alerts_per_hour);
        updateSeverityChart(s.alerts_by_severity);
        updateTypeChart(s.alerts_by_type);
    }

    function updateThreatLevel(level) {
        threatIndicator.className = `threat-indicator level-${level}`;
        threatText.textContent = level.toUpperCase();
    }


    // ══════════════════════════════════════════════════════════════
    //  Chart.js Charts
    // ══════════════════════════════════════════════════════════════

    // Chart.js global defaults for dark theme
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(148,163,184,0.08)';
    Chart.defaults.font.family = "'Inter', sans-serif";

    function updateAttackChart(alertsPerHour) {
        const labels = alertsPerHour.map(a => {
            const d = new Date(a.hour);
            return d.getHours().toString().padStart(2, '0') + ':00';
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
                    tension: 0.4,
                    pointRadius: 3,
                    pointBackgroundColor: '#22d3ee',
                    pointBorderColor: '#0a0e1a',
                    pointBorderWidth: 2,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#1a2540',
                        borderColor: 'rgba(34,211,238,0.3)',
                        borderWidth: 1,
                        titleFont: { weight: '600' },
                    },
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { maxTicksLimit: 12, font: { size: 11 } },
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(148,163,184,0.06)' },
                        ticks: { font: { size: 11 }, stepSize: 1 },
                    },
                },
            },
        });
    }

    function updateSeverityChart(bySeverity) {
        const labels = ['Low', 'Medium', 'High'];
        const data   = [bySeverity.low || 0, bySeverity.medium || 0, bySeverity.high || 0];
        const colors = ['#22d3ee', '#f59e0b', '#ef4444'];

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
                datasets: [{
                    data,
                    backgroundColor: colors,
                    borderColor: '#0a0e1a',
                    borderWidth: 3,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { padding: 16, usePointStyle: true, pointStyleWidth: 10 },
                    },
                },
            },
        });
    }

    function updateTypeChart(byType) {
        const labels = ['Signature', 'Port Scan', 'Brute Force', 'SYN Flood'];
        const data   = [
            byType.signature || 0,
            byType.port_scan || 0,
            byType.brute_force || 0,
            byType.syn_flood || 0,
        ];
        const colors = ['#8b5cf6', '#3b82f6', '#f59e0b', '#ef4444'];

        const ctx = document.getElementById('typeChart');
        if (!ctx) return;

        if (typeChart) {
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
                    backgroundColor: colors.map(c => c + '30'),
                    borderColor: colors,
                    borderWidth: 1,
                    borderRadius: 6,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: 'rgba(148,163,184,0.06)' },
                        ticks: { font: { size: 11 }, stepSize: 1 },
                    },
                    y: {
                        grid: { display: false },
                        ticks: { font: { size: 11 } },
                    },
                },
            },
        });
    }


    // ══════════════════════════════════════════════════════════════
    //  Initialisation
    // ══════════════════════════════════════════════════════════════

    (async function init() {
        await loadRecentAlerts();
        await fetchStats();
        connectWebSocket();

        // Refresh stats every 30s
        setInterval(fetchStats, 30000);
    })();

})();
