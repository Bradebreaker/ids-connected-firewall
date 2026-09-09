/**
 * firewall.js — Firewall rule editor page logic.
 *
 * Handles loading, creating, and deleting firewall rules
 * via the REST API with JWT authentication.
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

    function authHeaders() {
        return { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' };
    }

    // ── Global helpers (called from HTML) ───────────────────────
    window.logout = function () {
        localStorage.removeItem('ids_token');
        window.location.href = '/login';
    };

    window.toggleSidebar = function () {
        document.getElementById('sidebar').classList.toggle('mobile-open');
    };

    // ── Load rules ──────────────────────────────────────────────
    async function loadRules() {
        try {
            const res = await fetch(API_BASE + '/api/rules', { headers: authHeaders() });
            if (res.status === 401) { window.logout(); return; }
            const rules = await res.json();
            renderRules(rules);
        } catch (e) {
            console.error('Failed to load rules:', e);
        }
    }

    function renderRules(rules) {
        const tbody = document.getElementById('rulesTableBody');

        if (!rules.length) {
            tbody.innerHTML = `
                <tr><td colspan="9">
                    <div class="empty-state">
                        <div class="empty-icon">📋</div>
                        <p>No firewall rules configured</p>
                    </div>
                </td></tr>`;
            return;
        }

        tbody.innerHTML = rules.map(r => `
            <tr>
                <td><strong>${r.priority}</strong></td>
                <td class="ip-cell">${r.source_ip}</td>
                <td>${r.dest_port || 'Any'}</td>
                <td>${r.protocol || 'Any'}</td>
                <td><span class="table-badge ${r.action.toLowerCase()}">${r.action}</span></td>
                <td><span class="table-badge ${r.rule_type}">${r.rule_type.toUpperCase()}</span></td>
                <td>
                    <span class="table-badge ${r.is_temporary ? 'temporary' : 'permanent'}">
                        ${r.is_temporary ? 'TEMP' : 'PERM'}
                    </span>
                </td>
                <td class="text-muted">${r.expires_at ? new Date(r.expires_at).toLocaleString() : '—'}</td>
                <td>
                    <button class="btn btn-danger btn-sm" onclick="deleteRule(${r.id})">
                        Delete
                    </button>
                </td>
            </tr>
        `).join('');
    }

    // ── Delete rule ─────────────────────────────────────────────
    window.deleteRule = async function (id) {
        if (!confirm('Delete this firewall rule? The iptables entry will be removed.')) return;

        try {
            const res = await fetch(API_BASE + `/api/rules/${id}`, {
                method: 'DELETE',
                headers: authHeaders(),
            });
            if (res.ok || res.status === 204) {
                loadRules();
            } else {
                const err = await res.json();
                alert(err.detail || 'Failed to delete rule');
            }
        } catch (e) {
            alert('Network error');
        }
    };

    // ── Add rule modal ──────────────────────────────────────────
    window.openRuleModal = function () {
        document.getElementById('ruleModal').classList.remove('hidden');
    };

    window.closeRuleModal = function () {
        document.getElementById('ruleModal').classList.add('hidden');
    };

    window.toggleRuleTTL = function () {
        const show = document.getElementById('ruleTemp').value === 'temporary';
        document.getElementById('ruleTtlGroup').style.display = show ? 'block' : 'none';
    };

    document.getElementById('ruleForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const isTemp = document.getElementById('ruleTemp').value === 'temporary';
        const portVal = document.getElementById('rulePort').value;
        const protoVal = document.getElementById('ruleProto').value;

        const body = {
            source_ip: document.getElementById('ruleIp').value.trim(),
            action: document.getElementById('ruleAction').value,
            priority: parseInt(document.getElementById('rulePriority').value) || 100,
            is_temporary: isTemp,
        };

        if (portVal) body.dest_port = parseInt(portVal);
        if (protoVal) body.protocol = protoVal;
        if (isTemp) {
            body.ttl_seconds = parseInt(document.getElementById('ruleTTL').value) || 1800;
        }

        try {
            const res = await fetch(API_BASE + '/api/rules', {
                method: 'POST',
                headers: authHeaders(),
                body: JSON.stringify(body),
            });

            if (res.ok || res.status === 201) {
                window.closeRuleModal();
                loadRules();
            } else {
                const err = await res.json();
                alert(err.detail || 'Failed to create rule');
            }
        } catch (e) {
            alert('Network error');
        }
    });

    // ── Init ────────────────────────────────────────────────────
    loadRules();
    setInterval(loadRules, 15000);

})();
