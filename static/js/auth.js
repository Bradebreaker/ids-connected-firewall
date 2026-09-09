/**
 * auth.js — Login page logic.
 *
 * Handles the login form submission, sends credentials to the API,
 * stores the JWT token in localStorage, and redirects to the dashboard.
 */

(function () {
    'use strict';

    const API_BASE = '';

    // If already logged in, redirect to dashboard
    const existing = localStorage.getItem('ids_token');
    if (existing) {
        window.location.href = '/';
        return;
    }

    const form     = document.getElementById('loginForm');
    const errorDiv = document.getElementById('loginError');
    const loginBtn = document.getElementById('loginBtn');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideError();

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        if (!username || !password) {
            showError('Please enter both username and password.');
            return;
        }

        loginBtn.disabled = true;
        loginBtn.textContent = 'Signing in…';

        try {
            const res = await fetch(API_BASE + '/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });

            if (res.ok) {
                const data = await res.json();
                localStorage.setItem('ids_token', data.access_token);
                window.location.href = '/';
            } else {
                const err = await res.json();
                showError(err.detail || 'Invalid credentials');
            }
        } catch (err) {
            showError('Network error — is the server running?');
            console.error('Login error:', err);
        } finally {
            loginBtn.disabled = false;
            loginBtn.textContent = 'Sign In';
        }
    });

    function showError(msg) {
        errorDiv.textContent = msg;
        errorDiv.classList.add('show');
    }

    function hideError() {
        errorDiv.classList.remove('show');
    }
})();
