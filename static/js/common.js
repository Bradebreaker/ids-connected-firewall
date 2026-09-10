/**
 * static/js/common.js — Shared Utilities & Core Client Infrastructure
 * Provides centralized authentication, resilient WebSocket lifecycle,
 * API client with Bearer tokens, notifications, and attack link resolution.
 */

const IDS = {
    TOKEN_KEY: 'ids_token',

    // ── Authentication ───────────────────────────────────────────
    getToken() {
        return localStorage.getItem(this.TOKEN_KEY);
    },

    setToken(token) {
        localStorage.setItem(this.TOKEN_KEY, token);
    },

    logout() {
        localStorage.removeItem(this.TOKEN_KEY);
        window.location.href = '/login.html';
    },

    requireAuth() {
        const token = this.getToken();
        if (!token) {
            window.location.href = '/login.html';
            return false;
        }
        return true;
    },

    // ── API Client ───────────────────────────────────────────────
    async apiFetch(url, options = {}) {
        const token = this.getToken();
        const headers = {
            'Content-Type': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
            ...(options.headers || {})
        };

        try {
            const resp = await fetch(url, { ...options, headers });
            if (resp.status === 401 || resp.status === 403) {
                // Token invalid or expired
                this.logout();
                throw new Error('Session expired. Please log in again.');
            }
            return resp;
        } catch (err) {
            console.error(`API fetch error [${url}]:`, err);
            throw err;
        }
    },

    // ── Toast Notifications ──────────────────────────────────────
    showToast(message, type = 'info', duration = 3500) {
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.style.cssText = `
                position: fixed;
                bottom: 24px;
                right: 24px;
                z-index: 99999;
                display: flex;
                flex-direction: column;
                gap: 10px;
                pointer-events: none;
            `;
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        let bg = '#1e293b';
        let border = '#334155';
        let icon = 'ℹ️';
        if (type === 'success') { bg = '#064e3b'; border = '#059669'; icon = '✅'; }
        else if (type === 'error') { bg = '#7f1d1d'; border = '#dc2626'; icon = '❌'; }
        else if (type === 'warning') { bg = '#78350f'; border = '#d97706'; icon = '⚠️'; }

        toast.style.cssText = `
            background: ${bg};
            border: 1px solid ${border};
            color: #f8fafc;
            padding: 12px 18px;
            border-radius: 8px;
            font-size: 0.88rem;
            font-weight: 500;
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5);
            display: flex;
            align-items: center;
            gap: 10px;
            pointer-events: auto;
            transition: all 0.3s ease;
            transform: translateY(10px);
            opacity: 0;
        `;
        toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
        container.appendChild(toast);

        // Animate in
        requestAnimationFrame(() => {
            toast.style.transform = 'translateY(0)';
            toast.style.opacity = '1';
        });

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(10px)';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },

    // ── WebSocket Lifecycle ──────────────────────────────────────
    createWebSocket(onMessage, onStatusChange) {
        const token = this.getToken();
        if (!token) return null;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/api/ws/alerts?token=${encodeURIComponent(token)}`;

        let ws = null;
        let reconnectTimeout = null;
        let reconnectAttempts = 0;
        let isIntentionallyClosed = false;

        const connect = () => {
            if (onStatusChange) onStatusChange('CONNECTING');
            try {
                ws = new WebSocket(wsUrl);
            } catch (e) {
                if (onStatusChange) onStatusChange('ERROR');
                scheduleReconnect();
                return;
            }

            ws.onopen = () => {
                reconnectAttempts = 0;
                if (onStatusChange) onStatusChange('CONNECTED');
            };

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (onMessage) onMessage(data);
                } catch (e) {
                    console.error('Failed to parse WS message:', e);
                }
            };

            ws.onclose = (event) => {
                if (!isIntentionallyClosed) {
                    if (onStatusChange) onStatusChange('RECONNECTING');
                    scheduleReconnect();
                } else {
                    if (onStatusChange) onStatusChange('DISCONNECTED');
                }
            };

            ws.onerror = (error) => {
                console.warn('WebSocket encountered error:', error);
                if (onStatusChange) onStatusChange('ERROR');
            };
        };

        const scheduleReconnect = () => {
            if (isIntentionallyClosed) return;
            const delay = Math.min(1000 * Math.pow(1.5, reconnectAttempts), 15000);
            reconnectAttempts++;
            clearTimeout(reconnectTimeout);
            reconnectTimeout = setTimeout(() => {
                connect();
            }, delay);
        };

        connect();

        return {
            close() {
                isIntentionallyClosed = true;
                clearTimeout(reconnectTimeout);
                if (ws) ws.close();
            },
            send(data) {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(typeof data === 'string' ? data : JSON.stringify(data));
                }
            }
        };
    },

    // ── Attack Type URL & Display Helpers ────────────────────────
    getAttackSlug(attackType) {
        if (!attackType) return 'port-scan';
        const type = attackType.toLowerCase().replace(/_/g, '-');
        const mapping = {
            'signature': 'sql-injection',
            'ssrf': 'cloud-ssrf',
            'rce': 'php-rce',
            'command-injection': 'command-injection',
            'log4j': 'log4shell',
            'slow-http': 'slowloris',
        };
        return mapping[type] || type;
    },

    getAttackUrl(attackType) {
        const slug = this.getAttackSlug(attackType);
        return `/attacks/${slug}.html`;
    },

    formatAttackName(attackType) {
        if (!attackType) return 'Unknown Threat';
        const names = {
            'port_scan': 'Port Scan',
            'brute_force': 'Brute Force',
            'syn_flood': 'SYN Flood',
            'sql_injection': 'SQL Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'log4shell': 'Log4Shell (CVE-2021-44228)',
            'cloud_ssrf': 'Cloud SSRF',
            'path_traversal': 'Path Traversal',
            'php_rce': 'PHP Remote Code Execution',
            'shellshock': 'Shellshock',
            'http_request_smuggling': 'HTTP Request Smuggling',
            'api_abuse': 'API Abuse / BOLA',
            'credential_stuffing': 'Credential Stuffing',
            'jwt_attack': 'JWT / Auth Bypass',
            'dns_tunneling': 'DNS Tunneling',
            'slowloris': 'Slowloris (Slow HTTP)',
            'udp_flood': 'UDP Flood',
            'icmp_flood': 'ICMP Echo Flood',
            'command_injection': 'Command Injection',
            'ldap_injection': 'LDAP Injection',
            'xxe': 'XML External Entity (XXE)',
            'ssti': 'Server-Side Template Injection',
            'insecure_deserialization': 'Insecure Deserialization',
            'signature': 'Signature Pattern Match'
        };
        return names[attackType] || attackType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    },

    formatDate(dateVal) {
        if (!dateVal) return '—';
        try {
            const d = new Date(dateVal);
            if (isNaN(d.getTime())) return String(dateVal);
            return d.toISOString().replace('T', ' ').substring(0, 19);
        } catch (e) {
            return String(dateVal);
        }
    }
};
