import hmac
from functools import wraps

from flask import current_app, request, session

from server.config.config import ADMIN_API_TOKEN


PUBLIC_ENDPOINT_ATTR = '__rat_allow_anonymous__'


def allow_anonymous(view_func):
    """
    路由级匿名访问注解。
    被标记的接口可跳过 session / token 验证。
    """
    setattr(view_func, PUBLIC_ENDPOINT_ATTR, True)
    return view_func


def _unwrap_view_func(view_func):
    current = view_func
    visited = set()

    while current is not None and current not in visited:
        visited.add(current)
        if getattr(current, PUBLIC_ENDPOINT_ATTR, False):
            return current
        current = getattr(current, '__wrapped__', None)

    return view_func


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

    def is_public_request(self) -> bool:
        # Flask 静态资源路由，不需要单独配 URL 白名单
        if request.endpoint == 'static':
            return True

        if not request.endpoint:
            return False

        view_func = current_app.view_functions.get(request.endpoint)
        if view_func is None:
            return False

        unwrapped = _unwrap_view_func(view_func)
        return bool(getattr(unwrapped, PUBLIC_ENDPOINT_ATTR, False))