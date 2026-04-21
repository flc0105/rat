import hmac
from datetime import timedelta

from flask import Flask, redirect, request, send_from_directory

from server.config.config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    SESSION_COOKIE_NAME,
    WEB_AUTH_SESSION_DAYS,
    WEB_HTTP_UPLOAD_MAX_BYTES,
    WEB_SESSION_SECRET,
)
from server.web.api_response import WebApiResponder
from server.web.auth_guard import WebAuthGuard, allow_anonymous
from server.web.routes.agent import create_agent_blueprint
from server.web.routes.artifacts import create_artifacts_blueprint
from server.web.routes.background_jobs import create_background_job_blueprint
from server.web.routes.command_history import create_command_history_blueprint
from server.web.routes.connection_commands import create_connection_command_blueprint
from server.web.routes.pinned_paths import create_pinned_path_blueprint
from server.web.routes.remote_files import create_remote_files_blueprint
from server.web.routes.scripts import create_script_blueprint
from server.web.routes.system_inspection import create_system_inspection_blueprint
from server.web.routes.terminal import create_terminal_blueprint


def create_app(server_instance):
    app = Flask(__name__, static_folder='../../static', static_url_path='')
    app.config['MAX_CONTENT_LENGTH'] = WEB_HTTP_UPLOAD_MAX_BYTES
    app.config['SECRET_KEY'] = WEB_SESSION_SECRET
    app.config['SESSION_COOKIE_NAME'] = SESSION_COOKIE_NAME
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=WEB_AUTH_SESSION_DAYS)

    responder = WebApiResponder()
    auth_guard = WebAuthGuard()

    app.register_blueprint(create_connection_command_blueprint(server_instance))
    app.register_blueprint(create_background_job_blueprint(server_instance))
    app.register_blueprint(create_remote_files_blueprint(server_instance))
    app.register_blueprint(create_pinned_path_blueprint(server_instance))
    app.register_blueprint(create_system_inspection_blueprint(server_instance))
    app.register_blueprint(create_command_history_blueprint(server_instance))
    app.register_blueprint(create_artifacts_blueprint(server_instance))
    app.register_blueprint(create_agent_blueprint(server_instance))
    app.register_blueprint(create_script_blueprint(server_instance))
    app.register_blueprint(create_terminal_blueprint(server_instance))

    @app.before_request
    def enforce_authentication():
        if request.method == 'OPTIONS':
            return None

        if auth_guard.is_public_request():
            return None

        if auth_guard.is_authenticated():
            return None

        is_api_request = (request.path or '').startswith('/api/')
        if is_api_request:
            return responder.fail('Authentication required', 401)

        return redirect('/login.html')

    @app.get('/')
    def index():
        if not auth_guard.is_authenticated():
            return redirect('/login.html')
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/login.html')
    @allow_anonymous
    def login_page():
        if auth_guard.is_authenticated():
            return redirect('/')
        return send_from_directory(app.static_folder, 'login.html')

    @app.get('/api/auth/session')
    @allow_anonymous
    def auth_session():
        return responder.ok({
            'authenticated': auth_guard.is_authenticated(),
            'username': auth_guard.get_session_username() or ADMIN_USERNAME,
        })

    @app.post('/api/auth/login')
    @allow_anonymous
    def auth_login():
        payload = request.get_json(silent=True) or {}
        username = str(payload.get('username') or '').strip()
        password = str(payload.get('password') or '')

        if not username:
            return responder.fail('username is required', 400)
        if not password:
            return responder.fail('password is required', 400)

        if not hmac.compare_digest(username, ADMIN_USERNAME) or not hmac.compare_digest(password, ADMIN_PASSWORD):
            return responder.fail('Invalid username or password', 401)

        auth_guard.login_user(username)
        return responder.ok({
            'authenticated': True,
            'username': username,
            'session_days': WEB_AUTH_SESSION_DAYS,
        })

    @app.post('/api/auth/logout')
    def auth_logout():
        auth_guard.logout_user()
        return responder.ok({'authenticated': False})

    @app.errorhandler(413)
    def file_too_large(_):
        return responder.fail('File is too large', 413)

    return app