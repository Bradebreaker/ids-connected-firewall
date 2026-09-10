/**
 * static/js/alerts.js — Alerts Ledger & Deep-Dive Investigation Client Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    if (!IDS.requireAuth()) return;

    let currentPage = 0;
    const pageSize = 25;
    let totalAlerts = 0;

    // DOM references
    const searchInput = document.getElementById('filterSearch');
    const severitySelect = document.getElementById('filterSeverity');
    const attackTypeSelect = document.getElementById('filterAttackType');
    const timeSelect = document.getElementById('filterTime');
    const blockedSelect = document.getElementById('filterBlocked');
    const sortColumn = document.getElementById('sortColumn');
    const sortDir = document.getElementById('sortDir');
    const resultCount = document.getElementById('filterResultCount');
    const tableBody = document.getElementById('alertsTableBody');

    const btnPrev = document.getElementById('btnPrevPage');
    const btnNext = document.getElementById('btnNextPage');
    const pageIndicator = document.getElementById('pageIndicator');
    const btnRefresh = document.getElementById('btnRefreshAlerts');

    const btnExportCsv = document.getElementById('btnExportAlertsCsv');
    const btnExportJson = document.getElementById('btnExportAlertsJson');

    // Modal references
    const modal = document.getElementById('alertModal');
    const modalTitle = document.getElementById('modalAlertTitle');
    const modalSeverityBadge = document.getElementById('modalSeverityBadge');
    const modalReason = document.getElementById('modalMaliciousReason');
    const modalAlertId = document.getElementById('modalAlertId');
    const modalTimestamp = document.getElementById('modalTimestamp');
    const modalSourceIp = document.getElementById('modalSourceIp');
    const modalDestIp = document.getElementById('modalDestIp');
    const modalDestPort = document.getElementById('modalDestPort');
    const modalProtocol = document.getElementById('modalProtocol');
    const modalAttackType = document.getElementById('modalAttackType');
    const modalActionTaken = document.getElementById('modalActionTaken');
    const modalDescription = document.getElementById('modalDescription');
    const modalRawPacket = document.getElementById('modalRawPacket');
    const modalAttackIntelLink = document.getElementById('modalAttackIntelLink');

    // Parse URL params for drill-downs
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('filter') === 'today') {
        timeSelect.value = 'today';
    }
    if (urlParams.get('source')) {
        searchInput.value = urlParams.get('source');
    }
    if (urlParams.get('type')) {
        attackTypeSelect.value = urlParams.get('type');
    }

    // ── WebSocket Lifecycle ──────────────────────────────────────
    IDS.createWebSocket(
        (msg) => {
            if (msg.type === 'new_alert') {
                // If on page 0, auto-refresh table
                if (currentPage === 0) {
                    loadAlerts(false);
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

    // ── Load Alerts from API ─────────────────────────────────────
    async function loadAlerts(showLoading = true) {
        if (showLoading) {
            tableBody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:30px; color:#64748b;">Loading alerts...</td></tr>`;
        }

        const params = new URLSearchParams({
            limit: pageSize,
            offset: currentPage * pageSize,
            sort_by: sortColumn.value,
            sort_dir: sortDir.value,
        });

        if (searchInput.value.trim()) params.append('search', searchInput.value.trim());
        if (severitySelect.value) params.append('severity', severitySelect.value);
        if (attackTypeSelect.value) params.append('alert_type', attackTypeSelect.value);
        if (timeSelect.value) params.append('date_filter', timeSelect.value);
        if (blockedSelect.value) params.append('auto_blocked', blockedSelect.value);

        try {
            const resp = await IDS.apiFetch(`/api/alerts?${params.toString()}`);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            
            const total = parseInt(resp.headers.get('X-Total-Count') || '0', 10);
            totalAlerts = total;
            const alerts = await resp.json();

            renderTable(alerts);
            updatePagination();
        } catch (err) {
            tableBody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:30px; color:#ef4444;">Failed to load alerts: ${err.message}</td></tr>`;
            IDS.showToast('Unable to retrieve alerts from server', 'error');
        }
    }

    // ── Render Alerts Table ──────────────────────────────────────
    function renderTable(alerts) {
        if (!alerts || alerts.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:30px; color:#64748b;">No alerts found matching the current criteria.</td></tr>`;
            resultCount.textContent = 'Showing 0 alerts';
            return;
        }

        resultCount.textContent = `Showing ${alerts.length} of ${totalAlerts} total alerts`;
        tableBody.innerHTML = '';

        alerts.forEach(a => {
            const tr = document.createElement('tr');
            tr.style.cursor = 'pointer';

            const sevBadge = `<span class="badge badge-${a.severity}">${a.severity.toUpperCase()}</span>`;
            const actionBadge = a.auto_blocked 
                ? `<span class="badge badge-high" style="background:#7f1d1d;">BLOCKED</span>` 
                : `<span class="badge badge-low">ALERTED</span>`;
            
            const timeStr = IDS.formatDate(a.timestamp);
            const attackName = IDS.formatAttackName(a.alert_type);
            const attackUrl = IDS.getAttackUrl(a.alert_type);

            tr.innerHTML = `
                <td style="font-family:monospace; color:#64748b;">#${a.id}</td>
                <td style="font-family:monospace; font-size:0.8rem; color:#94a3b8;">${timeStr}</td>
                <td>${sevBadge}</td>
                <td><a href="${attackUrl}" class="table-link" onclick="event.stopPropagation();" style="color:#38bdf8; font-weight:600; text-decoration:none;">${attackName}</a></td>
                <td><code style="color:#38bdf8;">${a.source_ip}</code></td>
                <td><code>${a.dest_ip || '—'}</code></td>
                <td>${a.dest_port || '—'}</td>
                <td><span class="badge" style="background:rgba(255,255,255,0.06);">${a.protocol || '—'}</span></td>
                <td style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#cbd5e1;" title="${a.description}">${a.description}</td>
                <td>${actionBadge}</td>
            `;

            tr.addEventListener('click', () => {
                openAlertInvestigation(a);
            });

            tableBody.appendChild(tr);
        });
    }

    // ── Update Pagination Controls ───────────────────────────────
    function updatePagination() {
        const totalPages = Math.ceil(totalAlerts / pageSize) || 1;
        pageIndicator.textContent = `Page ${currentPage + 1} of ${totalPages}`;
        btnPrev.disabled = currentPage === 0;
        btnNext.disabled = (currentPage + 1) >= totalPages;
    }

    // ── Open Investigation Modal ─────────────────────────────────
    function openAlertInvestigation(a) {
        modalTitle.textContent = `Alert Investigation #${a.id} — ${IDS.formatAttackName(a.alert_type)}`;
        modalSeverityBadge.className = `badge badge-${a.severity}`;
        modalSeverityBadge.textContent = a.severity.toUpperCase();

        modalAlertId.textContent = `#${a.id}`;
        modalTimestamp.textContent = IDS.formatDate(a.timestamp);
        modalSourceIp.textContent = a.source_ip;
        modalDestIp.textContent = a.dest_ip || '192.168.1.10';
        modalDestPort.textContent = a.dest_port || '—';
        modalProtocol.textContent = a.protocol || 'TCP';
        modalAttackType.textContent = IDS.formatAttackName(a.alert_type);
        modalActionTaken.innerHTML = a.auto_blocked
            ? `<span style="color:#ef4444; font-weight:700;">🛑 Auto-Blocked in Firewall ACL</span>`
            : `<span style="color:#10b981; font-weight:700;">⚠️ Logged & Monitored</span>`;

        modalDescription.textContent = a.description;
        modalRawPacket.textContent = a.raw_packet || `${a.protocol} Packet from ${a.source_ip} to destination port ${a.dest_port}`;

        // Plain-English Reasoning Generator
        let reasoning = "";
        const type = (a.alert_type || '').toLowerCase();
        if (type.includes('port_scan') || type.includes('port-scan')) {
            reasoning = `The IDS sliding-window detector observed rapid connections to multiple distinct destination ports from host ${a.source_ip}. This reconnaissance behavior exceeded the configured threshold of 15 ports within a 60-second window, which is characteristic of an automated Nmap or masscan probe.`;
        } else if (type.includes('brute_force') || type.includes('brute-force')) {
            reasoning = `More than 10 connection attempts to authentication port ${a.dest_port} were observed from source ${a.source_ip} within 120 seconds. This exceeded the brute-force threshold, indicating an automated credential-guessing attack.`;
        } else if (type.includes('syn_flood') || type.includes('syn-flood')) {
            reasoning = `A volumetric flood of TCP SYN packets was received from ${a.source_ip} without completing the 3-way handshake. The packet arrival rate deviated by more than 2 standard deviations from the learned baseline mean.`;
        } else if (type.includes('sql_injection')) {
            reasoning = `Payload pattern matching detected an SQL injection exploit pattern ('OR 1=1' or 'UNION SELECT'). The attacker attempted to break SQL query structure to bypass authentication or exfiltrate database contents.`;
        } else if (type.includes('log4shell')) {
            reasoning = `A known JNDI lookup string (\${jndi:ldap://...}) was discovered inside packet headers. This matches the critical CVE-2021-44228 remote code execution exploit pattern.`;
        } else if (type.includes('cloud_ssrf') || type.includes('ssrf')) {
            reasoning = `A request targeting the cloud instance metadata service (169.254.169.254) was observed. Attackers use this to steal IAM roles and instance identity tokens in AWS/GCP/Azure environments.`;
        } else if (type.includes('http_request_smuggling')) {
            reasoning = `Conflicting Transfer-Encoding and Content-Length headers were detected in the HTTP stream, indicating an attempt to desynchronize frontend and backend HTTP proxies.`;
        } else {
            reasoning = `The IDS inspected packet contents and matched malicious patterns or volume anomalies defined in the active security policy. Description: "${a.description}".`;
        }

        modalReason.textContent = reasoning;
        modalAttackIntelLink.href = IDS.getAttackUrl(a.alert_type);

        modal.style.display = 'flex';
    }

    // ── Event Handlers ───────────────────────────────────────────
    searchInput.addEventListener('input', () => { currentPage = 0; loadAlerts(); });
    severitySelect.addEventListener('change', () => { currentPage = 0; loadAlerts(); });
    attackTypeSelect.addEventListener('change', () => { currentPage = 0; loadAlerts(); });
    timeSelect.addEventListener('change', () => { currentPage = 0; loadAlerts(); });
    blockedSelect.addEventListener('change', () => { currentPage = 0; loadAlerts(); });
    sortColumn.addEventListener('change', () => { currentPage = 0; loadAlerts(); });
    sortDir.addEventListener('change', () => { currentPage = 0; loadAlerts(); });

    btnRefresh.addEventListener('click', () => {
        btnRefresh.textContent = 'Refreshing...';
        loadAlerts().then(() => {
            btnRefresh.textContent = '🔄 Refresh';
            IDS.showToast('Alerts ledger synchronized', 'info');
        });
    });

    btnPrev.addEventListener('click', () => {
        if (currentPage > 0) {
            currentPage--;
            loadAlerts();
        }
    });

    btnNext.addEventListener('click', () => {
        currentPage++;
        loadAlerts();
    });

    // ── Export Handlers ──────────────────────────────────────────
    btnExportCsv.addEventListener('click', () => {
        const p = timeSelect.value || 'all';
        window.open(`/api/report/csv?period=${p}`, '_blank');
        IDS.showToast('Downloading Alerts CSV export...', 'info');
    });

    btnExportJson.addEventListener('click', () => {
        const p = timeSelect.value || 'all';
        window.open(`/api/report/json?period=${p}`, '_blank');
        IDS.showToast('Downloading Security JSON archive...', 'info');
    });

    // Initial load
    loadAlerts();
});
