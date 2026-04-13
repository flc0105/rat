import hmac
import re
from urllib.parse import quote

from flask import request, session

from server.config.config import ADMIN_API_TOKEN


PUBLIC_STATIC_PATHS = {
    '/login.html',
    '/auth.js',
    '/app.css',
    '/favicon.ico',
}

PUBLIC_API_PATHS = {
    '/api/auth/login',
    '/api/auth/logout',
    '/api/auth/session',
}

# 这些接口由 Agent 或后台任务主动调用，保持免鉴权以避免破坏现有链路。
PUBLIC_API_PATTERNS = [
    (None, re.compile(r'^/api/files/upload$')),
    (None, re.compile(r'^/api/background-jobs/report$')),
    ('GET', re.compile(r'^/api/jobs/download$')),
    ('GET', re.compile(r'^/api/jobs/list$')),
    ('GET', re.compile(r'^/api/connections/[^/]+/control$')),
    ('GET', re.compile(r'^/api/upload-tmp/[^/]+/[^/]+$')),
    ('POST', re.compile(r'^/api/agent/build$')),
    ('GET', re.compile(r'^/api/agent/download/[^/]+$')),
]


class WebAuthGuard:
    SESSION_AUTH_FLAG = 'rat_admin_authenticated'
    SESSION_USER_KEY = 'rat_admin_username'

    def _get_authorization_token(self) -> str:
        header = str(request.headers.get('Authorization') or '').strip()
        if header:
            parts = header.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                return parts[1].strip()
            return header

        for header_name in ('X-Auth-Token', 'X-API-Token'):
            value = str(request.headers.get(header_name) or '').strip()
            if value:
                return value

        return ''

    def has_valid_static_token(self) -> bool:
        expected = str(ADMIN_API_TOKEN or '').strip()
        provided = self._get_authorization_token()
        if not expected or not provided:
            return False
        return hmac.compare_digest(provided, expected)

    def has_valid_session(self) -> bool:
        return bool(session.get(self.SESSION_AUTH_FLAG))

    def is_authenticated(self) -> bool:
        return self.has_valid_static_token() or self.has_valid_session()

    def get_session_username(self) -> str:
        return str(session.get(self.SESSION_USER_KEY) or '').strip()

    def login_user(self, username: str):
        session.permanent = True
        session[self.SESSION_AUTH_FLAG] = True
        session[self.SESSION_USER_KEY] = str(username or '').strip()

    def logout_user(self):
        session.pop(self.SESSION_AUTH_FLAG, None)
        session.pop(self.SESSION_USER_KEY, None)
        session.clear()

    def is_public_static_path(self, path: str) -> bool:
        normalized = str(path or '').strip()
        if normalized in PUBLIC_STATIC_PATHS:
            return True
        return normalized.startswith('/monaco-editor/')

    def is_public_api_path(self, path: str, method: str) -> bool:
        normalized_path = str(path or '').strip()
        normalized_method = str(method or '').upper()

        if normalized_path in PUBLIC_API_PATHS:
            return True

        for allowed_method, pattern in PUBLIC_API_PATTERNS:
            if allowed_method is not None and normalized_method != allowed_method:
                continue
            if pattern.match(normalized_path):
                return True

        return False

    def build_login_redirect_target(self) -> str:
        raw_query = request.query_string.decode('utf-8', errors='ignore')
        full_path = request.path
        if raw_query:
            full_path = f'{full_path}?{raw_query}'
        return f'/login.html?redirect={quote(full_path, safe="")}'