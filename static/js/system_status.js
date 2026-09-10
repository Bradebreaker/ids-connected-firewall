/**
 * static/js/system_status.js — System Health & Observability Client Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    if (!IDS.requireAuth()) return;

    const uptimeVal = document.getElementById('sysUptimeVal');
    const statPackets = document.getElementById('statSysPackets');
    const statAlerts = document.getElementById('statSysAlerts');
    const statBlocks = document.getElementById('statSysBlocks');
    const statWsClients = document.getElementById('statSysWsClients');
    const grid = document.getElementById('componentsGrid');

    const envOs = document.getElementById('envOs');
    const envPython = document.getElementById('envPython');
    const envVersion = document.getElementById('envVersion');
    const envDbSize = document.getElementById('envDbSize');

    const btnRefresh = document.getElementById('btnRefreshStatus');

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

    // ── Fetch Status ─────────────────────────────────────────────
    async function loadStatus() {
        try {
            const resp = await IDS.apiFetch('/api/system/status');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            renderStatus(data);
        } catch (err) {
            grid.innerHTML = `<div style="color:#ef4444; padding:20px;">Failed to load subsystem health: ${err.message}</div>`;
        }
    }

    // ── Render Status ────────────────────────────────────────────
    function renderStatus(data) {
        uptimeVal.textContent = data.uptime;
        statPackets.textContent = data.metrics.packets_processed;
        statAlerts.textContent = data.metrics.total_alerts;
        statBlocks.textContent = data.metrics.active_blocks;
        statWsClients.textContent = data.metrics.websocket_clients;

        envOs.textContent = data.environment.os;
        envPython.textContent = `Python ${data.environment.python}`;
        envVersion.textContent = `v${data.environment.app_version}`;
        envDbSize.textContent = `${data.metrics.db_size_kb} KB`;

        const compKeys = Object.keys(data.components);
        grid.innerHTML = compKeys.map(k => {
            const c = data.components[k];
            let badgeClass = 'status-badge-online';
            let dot = '●';
            if (c.status === 'DEGRADED') {
                badgeClass = 'status-badge-degraded';
            } else if (c.status === 'OFFLINE' || c.status === 'ERROR') {
                badgeClass = 'status-badge-error';
            }

            return `
                <div class="status-component-card">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                        <h4 style="margin:0; font-size:0.95rem; color:#fff;">${c.name}</h4>
                        <span class="${badgeClass}">${dot} ${c.status}</span>
                    </div>
                    <div style="font-size:0.82rem; color:#94a3b8; font-family:'JetBrains Mono',monospace; margin-top:4px;">
                        ${c.detail}
                    </div>
                </div>
            `;
        }).join('');
    }

    btnRefresh.addEventListener('click', () => {
        btnRefresh.textContent = 'Refreshing...';
        loadStatus().then(() => {
            btnRefresh.textContent = '🔄 Refresh Diagnostics';
            IDS.showToast('Subsystem diagnostics synchronized', 'info');
        });
    });

    // Auto-refresh every 10 seconds on this page
    setInterval(loadStatus, 10000);

    // Initial load
    loadStatus();
});
