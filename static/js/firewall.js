/**
 * static/js/firewall.js — Firewall ACL & Command Center Client Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    if (!IDS.requireAuth()) return;

    const tableBody = document.getElementById('rulesTableBody');
    const ruleCountEl = document.getElementById('fwRuleCount');
    const btnRefresh = document.getElementById('btnRefreshRules');

    const addModal = document.getElementById('addRuleModal');
    const inputSourceIp = document.getElementById('ruleSourceIp');
    const inputPriority = document.getElementById('rulePriority');
    const inputDestPort = document.getElementById('ruleDestPort');
    const selectProtocol = document.getElementById('ruleProtocol');
    const selectAction = document.getElementById('ruleAction');
    const selectDuration = document.getElementById('ruleDuration');
    const btnSubmitRule = document.getElementById('btnSubmitRule');

    // ── WebSocket Lifecycle ──────────────────────────────────────
    IDS.createWebSocket(
        (msg) => {
            if (msg.type === 'ip_blocked' || msg.type === 'ip_unblocked') {
                loadRules();
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

    // ── Load Rules ───────────────────────────────────────────────
    async function loadRules() {
        try {
            const resp = await IDS.apiFetch('/api/rules');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const rules = await resp.json();
            renderRules(rules);
        } catch (err) {
            tableBody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:30px; color:#ef4444;">Failed to load firewall ACL: ${err.message}</td></tr>`;
        }
    }

    // ── Render Table ─────────────────────────────────────────────
    function renderRules(rules) {
        if (!rules || rules.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:30px; color:#64748b;">No active firewall rules in ACL. All nominal packets accepted.</td></tr>`;
            if (ruleCountEl) ruleCountEl.textContent = '0 Active';
            return;
        }

        if (ruleCountEl) ruleCountEl.textContent = `${rules.filter(r => r.is_active).length} Active`;
        tableBody.innerHTML = '';

        rules.forEach(r => {
            const tr = document.createElement('tr');

            const actionBadge = r.action === 'DROP'
                ? `<span class="badge badge-high" style="background:#7f1d1d;">DROP</span>`
                : `<span class="badge badge-low">ACCEPT</span>`;

            const statusBadge = r.is_active
                ? `<span class="badge" style="background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3);">● ACTIVE</span>`
                : `<span class="badge" style="background:#334155; color:#94a3b8;">○ INACTIVE</span>`;

            const typeBadge = `<span class="badge badge-medium" style="font-size:0.75rem;">${(r.rule_type || 'MANUAL').toUpperCase()}</span>`;
            const durationText = r.is_temporary ? '<span style="color:#f59e0b;">Temporary</span>' : '<span style="color:#94a3b8;">Permanent</span>';

            tr.innerHTML = `
                <td><strong>#${r.priority}</strong></td>
                <td style="color:#94a3b8;">INPUT</td>
                <td><code style="color:#38bdf8; font-weight:700;">${r.source_ip}</code></td>
                <td>${r.dest_port || 'ANY'}</td>
                <td>${(r.protocol || 'ANY').toUpperCase()}</td>
                <td>${actionBadge}</td>
                <td>${typeBadge}</td>
                <td>${durationText}</td>
                <td>${statusBadge}</td>
                <td style="text-align:right;">
                    <button class="btn btn-ghost btn-del-rule" data-id="${r.id}" style="padding:4px 10px; font-size:0.75rem; color:#ef4444;" title="Delete rule">Delete</button>
                </td>
            `;

            tableBody.appendChild(tr);
        });

        document.querySelectorAll('.btn-del-rule').forEach(btn => {
            btn.addEventListener('click', async () => {
                const id = btn.dataset.id;
                if (!confirm(`Are you sure you want to delete firewall rule #${id}?`)) return;

                try {
                    const resp = await IDS.apiFetch(`/api/rules/${id}`, { method: 'DELETE' });
                    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                    IDS.showToast(`Firewall rule #${id} purged from ACL`, 'success');
                    loadRules();
                } catch (e) {
                    IDS.showToast(`Failed to delete rule: ${e.message}`, 'error');
                }
            });
        });
    }

    // ── Add Rule Modal ───────────────────────────────────────────
    window.openAddRuleModal = function() {
        inputSourceIp.value = '';
        inputDestPort.value = '';
        inputPriority.value = '100';
        addModal.style.display = 'flex';
    };

    btnSubmitRule.addEventListener('click', async () => {
        const ip = inputSourceIp.value.trim();
        if (!ip) {
            IDS.showToast('Please enter a valid source host IP.', 'warning');
            return;
        }

        const body = {
            source_ip: ip,
            priority: parseInt(inputPriority.value || '100', 10),
            dest_port: inputDestPort.value ? parseInt(inputDestPort.value, 10) : null,
            protocol: selectProtocol.value || null,
            action: selectAction.value,
            is_temporary: selectDuration.value === 'temporary',
        };

        try {
            btnSubmitRule.disabled = true;
            btnSubmitRule.textContent = 'Deploying...';
            const resp = await IDS.apiFetch('/api/rules', {
                method: 'POST',
                body: JSON.stringify(body)
            });
            if (!resp.ok) {
                const errData = await resp.json().catch(() => ({}));
                throw new Error(errData.detail || `HTTP ${resp.status}`);
            }
            IDS.showToast(`Rule for ${ip} deployed into firewall ACL!`, 'success');
            addModal.style.display = 'none';
            loadRules();
        } catch (err) {
            IDS.showToast(`Rule deployment failed: ${err.message}`, 'error');
        } finally {
            btnSubmitRule.disabled = false;
            btnSubmitRule.textContent = 'Deploy Rule';
        }
    });

    btnRefresh.addEventListener('click', () => {
        btnRefresh.textContent = 'Refreshing...';
        loadRules().then(() => {
            btnRefresh.textContent = '🔄 Refresh State';
            IDS.showToast('Firewall ACL state synchronized', 'info');
        });
    });

    // Initial load
    loadRules();
});
