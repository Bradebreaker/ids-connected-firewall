/**
 * static/js/blocked.js — Quarantined Host Management Client Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    if (!IDS.requireAuth()) return;

    let pendingUnblockIp = null;

    const tableBody = document.getElementById('blockedTableBody');
    const btnRefresh = document.getElementById('btnRefreshBlocks');
    const unblockModal = document.getElementById('unblockModal');
    const unblockTargetIp = document.getElementById('unblockTargetIp');
    const btnConfirmUnblock = document.getElementById('btnConfirmUnblock');

    const manualModal = document.getElementById('manualBlockModal');
    const manualIpInput = document.getElementById('manualIpInput');
    const manualReasonInput = document.getElementById('manualReasonInput');
    const manualDurationSelect = document.getElementById('manualDurationSelect');
    const btnSubmitManualBlock = document.getElementById('btnSubmitManualBlock');

    // ── WebSocket Lifecycle ──────────────────────────────────────
    IDS.createWebSocket(
        (msg) => {
            if (msg.type === 'ip_blocked' || msg.type === 'ip_unblocked') {
                loadBlockedIps();
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

    // ── Fetch Blocked Hosts ──────────────────────────────────────
    async function loadBlockedIps() {
        try {
            const resp = await IDS.apiFetch('/api/blocked');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            renderTable(data);
        } catch (err) {
            tableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:#ef4444;">Failed to load blocked hosts: ${err.message}</td></tr>`;
        }
    }

    // ── Render Table ─────────────────────────────────────────────
    function renderTable(hosts) {
        if (!hosts || hosts.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:#64748b;">No active host quarantines in place. Nominal perimeter status.</td></tr>`;
            return;
        }

        tableBody.innerHTML = '';
        hosts.forEach(h => {
            const tr = document.createElement('tr');

            const isExpired = h.expires_at && new Date(h.expires_at).getTime() < Date.now();
            const statusBadge = isExpired
                ? `<span class="badge" style="background:#334155; color:#94a3b8;">EXPIRED</span>`
                : (h.is_permanent 
                    ? `<span class="badge badge-high">PERMANENT</span>` 
                    : `<span class="badge badge-medium">AUTO-BLOCKED</span>`);

            const blockedAtStr = IDS.formatDate(h.blocked_at);
            const expiresAtStr = h.expires_at ? IDS.formatDate(h.expires_at) : 'Permanent';

            tr.innerHTML = `
                <td><code style="color:#38bdf8; font-weight:700; font-size:0.9rem;">${h.ip_address}</code></td>
                <td>${h.reason && h.reason.includes(':') ? h.reason.split(':')[0] : 'Intrusion Attempt'}</td>
                <td style="color:#cbd5e1; max-width:240px; overflow:hidden; text-overflow:ellipsis;" title="${h.reason || ''}">${h.reason || 'Security Policy Violation'}</td>
                <td><span class="badge badge-high">HIGH</span></td>
                <td style="font-family:monospace; font-size:0.8rem; color:#94a3b8;">${blockedAtStr}</td>
                <td style="font-family:monospace; font-size:0.8rem; color:#94a3b8;">${expiresAtStr}</td>
                <td>${statusBadge}</td>
                <td style="text-align:right;">
                    <button class="btn btn-ghost btn-copy" data-ip="${h.ip_address}" style="padding:4px 8px; font-size:0.75rem;" title="Copy IP">📋 Copy</button>
                    <button class="btn btn-secondary btn-extend" data-ip="${h.ip_address}" style="padding:4px 8px; font-size:0.75rem;" title="Extend block duration">⏳ Extend</button>
                    <button class="btn btn-primary btn-unblock" data-ip="${h.ip_address}" style="padding:4px 8px; font-size:0.75rem; background:#dc2626; border-color:#ef4444;">Unblock</button>
                </td>
            `;

            tableBody.appendChild(tr);
        });

        // Attach action handlers
        document.querySelectorAll('.btn-copy').forEach(btn => {
            btn.addEventListener('click', () => {
                navigator.clipboard.writeText(btn.dataset.ip);
                IDS.showToast(`IP ${btn.dataset.ip} copied to clipboard!`, 'info');
            });
        });

        document.querySelectorAll('.btn-extend').forEach(btn => {
            btn.addEventListener('click', async () => {
                const ip = btn.dataset.ip;
                try {
                    await IDS.apiFetch('/api/block', {
                        method: 'POST',
                        body: JSON.stringify({ ip_address: ip, reason: 'Operator extended quarantine duration', is_permanent: true })
                    });
                    IDS.showToast(`Quarantine extended to Permanent for ${ip}`, 'success');
                    loadBlockedIps();
                } catch (e) {
                    IDS.showToast(`Failed to extend block: ${e.message}`, 'error');
                }
            });
        });

        document.querySelectorAll('.btn-unblock').forEach(btn => {
            btn.addEventListener('click', () => {
                pendingUnblockIp = btn.dataset.ip;
                unblockTargetIp.textContent = pendingUnblockIp;
                unblockModal.style.display = 'flex';
            });
        });
    }

    // ── Confirm Unblock ──────────────────────────────────────────
    btnConfirmUnblock.addEventListener('click', async () => {
        if (!pendingUnblockIp) return;
        try {
            btnConfirmUnblock.disabled = true;
            btnConfirmUnblock.textContent = 'Unblocking...';
            const resp = await IDS.apiFetch('/api/unblock', {
                method: 'POST',
                body: JSON.stringify({ ip_address: pendingUnblockIp })
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            IDS.showToast(`Successfully unblocked ${pendingUnblockIp}`, 'success');
            unblockModal.style.display = 'none';
            loadBlockedIps();
        } catch (err) {
            IDS.showToast(`Unblock failed: ${err.message}`, 'error');
        } finally {
            btnConfirmUnblock.disabled = false;
            btnConfirmUnblock.textContent = 'Confirm Unblock';
        }
    });

    // ── Manual Block ─────────────────────────────────────────────
    window.openManualBlockModal = function() {
        manualIpInput.value = '';
        manualReasonInput.value = '';
        manualModal.style.display = 'flex';
    };

    btnSubmitManualBlock.addEventListener('click', async () => {
        const ip = manualIpInput.value.trim();
        if (!ip) {
            IDS.showToast('Please enter a valid IP address.', 'warning');
            return;
        }

        const reason = manualReasonInput.value.trim() || 'Manual operator enforcement';
        const isPerm = manualDurationSelect.value === 'permanent';

        try {
            btnSubmitManualBlock.disabled = true;
            btnSubmitManualBlock.textContent = 'Enforcing...';
            const resp = await IDS.apiFetch('/api/block', {
                method: 'POST',
                body: JSON.stringify({ ip_address: ip, reason: reason, is_permanent: isPerm })
            });
            if (!resp.ok) {
                const errData = await resp.json().catch(() => ({}));
                throw new Error(errData.detail || `HTTP ${resp.status}`);
            }
            IDS.showToast(`Host ${ip} successfully quarantined in firewall!`, 'success');
            manualModal.style.display = 'none';
            loadBlockedIps();
        } catch (err) {
            IDS.showToast(`Block failed: ${err.message}`, 'error');
        } finally {
            btnSubmitManualBlock.disabled = false;
            btnSubmitManualBlock.textContent = 'Enforce Block';
        }
    });

    btnRefresh.addEventListener('click', () => {
        btnRefresh.textContent = 'Refreshing...';
        loadBlockedIps().then(() => {
            btnRefresh.textContent = '🔄 Refresh';
            IDS.showToast('Quarantined hosts synchronized', 'info');
        });
    });

    // Initial load
    loadBlockedIps();
});
