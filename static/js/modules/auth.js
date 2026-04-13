(function () {
    const LOGIN_PAGE = '/login.html';
    const SESSION_URL = '/api/auth/session';
    const LOGOUT_URL = '/api/auth/logout';
    const originalFetch = window.fetch.bind(window);

    function isLoginPage() {
        return window.location.pathname === '/login.html';
    }

    function buildRedirectUrl() {
        const current = `${window.location.pathname}${window.location.search}${window.location.hash}` || '/';
        return `${LOGIN_PAGE}?redirect=${encodeURIComponent(current)}`;
    }

    function redirectToLogin() {
        if (isLoginPage()) return;
        window.location.replace(buildRedirectUrl());
    }

    async function fetchWithAuth(input, init = {}) {
        const config = {...init};
        if (!config.credentials) {
            config.credentials = 'same-origin';
        }

        const response = await originalFetch(input, config);
        if (response.status === 401) {
            redirectToLogin();
        }
        return response;
    }

    async function ensureAuthenticated() {
        if (isLoginPage()) return;

        try {
            const response = await fetchWithAuth(SESSION_URL, {
                method: 'GET',
                cache: 'no-store',
            });

            if (!response.ok) {
                redirectToLogin();
                return;
            }

            const payload = await response.json();
            const authenticated = !!(payload && payload.data && payload.data.authenticated);
            if (!authenticated) {
                redirectToLogin();
            }
        } catch (_error) {
            redirectToLogin();
        }
    }

    async function logout() {
        try {
            await fetchWithAuth(LOGOUT_URL, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: '{}',
            });
        } catch (_error) {
        }
        window.location.replace(LOGIN_PAGE);
    }

    window.fetch = fetchWithAuth;
    window.RatAuth = {logout};

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', ensureAuthenticated);
    } else {
        ensureAuthenticated();
    }
})();