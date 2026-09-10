/**
 * static/js/auth.js — Authentication gateway logic.
 * Handles credential verification, JWT storage, remember-me handle persistence,
 * live backend heartbeat checks, and subtle cyber canvas animation.
 */

(function () {
    'use strict';

    const TOKEN_KEY = 'ids_token';

    // If already logged in, redirect to dashboard
    const existing = localStorage.getItem(TOKEN_KEY);
    if (existing) {
        window.location.href = '/index.html';
        return;
    }

    const form     = document.getElementById('loginForm');
    const errorDiv = document.getElementById('loginError');
    const loginBtn = document.getElementById('loginBtn');
    const togglePw = document.getElementById('togglePassword');
    const pwInput  = document.getElementById('password');
    const userInput= document.getElementById('username');
    const rememberMe = document.getElementById('rememberMe');

    // Populate remembered username if available
    const savedUser = localStorage.getItem('remembered_handle');
    if (savedUser && userInput) {
        userInput.value = savedUser;
        if (rememberMe) rememberMe.checked = true;
    }

    // Toggle password visibility
    if (togglePw && pwInput) {
        togglePw.addEventListener('click', () => {
            const isPassword = pwInput.type === 'password';
            pwInput.type = isPassword ? 'text' : 'password';
            togglePw.textContent = isPassword ? '🙈' : '👁';
        });
    }

    // Ping system status for gateway indicator
    async function checkGatewayHealth() {
        const apiDot = document.getElementById('loginApiDot');
        const apiStatus = document.getElementById('loginApiStatus');
        const fwDot = document.getElementById('loginFwDot');
        const fwStatus = document.getElementById('loginFwStatus');

        try {
            const resp = await fetch('/api/system/status');
            if (resp.ok) {
                const data = await resp.json();
                if (apiStatus) {
                    apiStatus.textContent = 'ONLINE';
                    if (apiDot) apiDot.className = 'status-dot online';
                }
                if (fwStatus && data.components && data.components.firewall_manager) {
                    const fwState = data.components.firewall_manager.status || 'ACTIVE';
                    fwStatus.textContent = fwState.toUpperCase();
                    if (fwDot) fwDot.className = `status-dot ${fwState === 'active' || fwState === 'online' ? 'active' : 'online'}`;
                }
            } else {
                throw new Error('Non-200 response');
            }
        } catch (e) {
            if (apiStatus) {
                apiStatus.textContent = 'DEGRADED';
                if (apiDot) apiDot.className = 'status-dot offline';
            }
        }
    }

    // Form submission
    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            hideError();

            const username = userInput.value.trim();
            const password = pwInput.value;

            if (!username || !password) {
                showError('Please enter operator credentials.');
                return;
            }

            loginBtn.disabled = true;
            loginBtn.innerHTML = `<span class="spinner" style="display:inline-block; width:14px; height:14px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:8px;"></span> Authenticating...`;

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password }),
                });

                if (res.ok) {
                    const data = await res.json();
                    localStorage.setItem(TOKEN_KEY, data.access_token);

                    if (rememberMe && rememberMe.checked) {
                        localStorage.setItem('remembered_handle', username);
                    } else {
                        localStorage.removeItem('remembered_handle');
                    }

                    window.location.href = '/index.html';
                } else {
                    const err = await res.json().catch(() => ({}));
                    showError(err.detail || 'Invalid operator credentials. Access denied.');
                }
            } catch (err) {
                showError('Gateway connection failed — verify backend daemon is active.');
                console.error('Login error:', err);
            } finally {
                loginBtn.disabled = false;
                loginBtn.textContent = 'Sign In to Console';
            }
        });
    }

    function showError(msg) {
        if (!errorDiv) return;
        errorDiv.textContent = msg;
        errorDiv.style.display = 'block';
    }

    function hideError() {
        if (!errorDiv) return;
        errorDiv.style.display = 'none';
    }

    checkGatewayHealth();

    // ── Subtle Cyber Canvas Mesh Animation ───────────────────────
    const canvas = document.getElementById('cyberCanvas');
    if (canvas && canvas.getContext) {
        const ctx = canvas.getContext('2d');
        let width = canvas.width = window.innerWidth;
        let height = canvas.height = window.innerHeight;

        window.addEventListener('resize', () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        });

        const numNodes = Math.min(35, Math.floor(width / 35));
        const nodes = [];

        for (let i = 0; i < numNodes; i++) {
            nodes.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.4,
                vy: (Math.random() - 0.5) * 0.4,
                radius: Math.random() * 1.5 + 1
            });
        }

        function draw() {
            ctx.clearRect(0, 0, width, height);

            // Draw connecting lines
            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) {
                    const dx = nodes[i].x - nodes[j].x;
                    const dy = nodes[i].y - nodes[j].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 130) {
                        ctx.beginPath();
                        ctx.strokeStyle = `rgba(56, 189, 248, ${0.15 * (1 - dist / 130)})`;
                        ctx.lineWidth = 0.8;
                        ctx.moveTo(nodes[i].x, nodes[i].y);
                        ctx.lineTo(nodes[j].x, nodes[j].y);
                        ctx.stroke();
                    }
                }
            }

            // Draw nodes
            for (let i = 0; i < nodes.length; i++) {
                const n = nodes[i];
                n.x += n.vx;
                n.y += n.vy;

                if (n.x < 0 || n.x > width) n.vx *= -1;
                if (n.y < 0 || n.y > height) n.vy *= -1;

                ctx.beginPath();
                ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(56, 189, 248, 0.4)';
                ctx.fill();
            }

            requestAnimationFrame(draw);
        }

        requestAnimationFrame(draw);
    }
})();
