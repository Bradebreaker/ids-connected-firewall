/**
 * static/js/nav.js — Global Navigation Component
 * Renders and synchronizes the professional SOC sidebar across all pages.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Only render if a container with class or id sidebar exists or create one
    const sidebarEl = document.getElementById('sidebar');
    if (!sidebarEl) return;

    const currentPath = window.location.pathname.toLowerCase();

    const navItems = [
        { section: 'MONITORING' },
        { label: 'Dashboard', icon: '📊', path: '/index.html', aliases: ['/', '/index', '/index.html'] },
        { label: 'Live Traffic', icon: '📡', path: '/traffic.html', aliases: ['/traffic', '/traffic.html'] },
        { label: 'Alerts', icon: '🔔', path: '/alerts.html', aliases: ['/alerts', '/alerts.html'] },
        { label: 'Attack Intelligence', icon: '⚔️', path: '/attack-intelligence.html', aliases: ['/attacks', '/attack-intelligence', '/attack-intelligence.html', '/attacks.html'] },
        { section: 'ENFORCEMENT' },
        { label: 'Blocked IPs', icon: '🚫', path: '/blocked-ips.html', aliases: ['/blocked', '/blocked-ips', '/blocked-ips.html', '/blocked.html'] },
        { label: 'Firewall Rules', icon: '📋', path: '/firewall-rules.html', aliases: ['/rules', '/firewall-rules', '/firewall-rules.html', '/rules.html'] },
        { section: 'GOVERNANCE' },
        { label: 'Security Reports', icon: '📑', path: '/reports.html', aliases: ['/reports', '/reports.html'] },
        { label: 'System Status', icon: '⚡', path: '/system-status.html', aliases: ['/system-status', '/system-status.html'] }
    ];

    let html = `
        <div class="sidebar-brand">
            <div class="brand-icon">🛡️</div>
            <div>
                <h1>IDS Firewall</h1>
                <span class="version">v1.0.0</span>
            </div>
        </div>
        <nav class="sidebar-nav">
    `;

    navItems.forEach(item => {
        if (item.section) {
            html += `<div class="nav-section-title">${item.section}</div>`;
        } else {
            const isActive = item.aliases.some(a => currentPath === a || (currentPath.endsWith(a) && a !== '/'));
            const activeClass = isActive ? 'active' : '';
            html += `
                <a href="${item.path}" class="nav-item ${activeClass}">
                    <span class="nav-icon">${item.icon}</span>
                    <span>${item.label}</span>
                </a>
            `;
        }
    });

    html += `
        </nav>
        <div class="sidebar-footer">
            <div class="user-profile-badge" style="margin-bottom:12px; padding:8px 12px; background:rgba(255,255,255,0.03); border-radius:6px; font-size:0.8rem; color:#94a3b8; display:flex; align-items:center; gap:8px;">
                <span style="color:#10b981;">●</span> <span style="color:#e2e8f0; font-weight:600;">admin</span> (SOC Operator)
            </div>
            <button class="logout-btn" onclick="IDS.logout()">
                <span>🚪</span><span>Log Out</span>
            </button>
        </div>
    `;

    sidebarEl.innerHTML = html;
});
