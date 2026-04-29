from flask import Blueprint, send_file

from server.web.api_response import WebApiResponder
from server.web.auth_guard import allow_anonymous
from server.web.request_parsers import get_json_payload


def create_agent_blueprint(server_instance):
    blueprint = Blueprint('agent', __name__)
    web_service = server_instance.web_service
    agent_api = web_service.agent_api
    responder = WebApiResponder()

    @blueprint.post('/api/agent/build')
    @allow_anonymous
    def build_agent():
        """构建 Agent"""

        def _execute():
            payload = get_json_payload()
            server_host = (payload.get('server_host') or '').strip()
            server_port = payload.get('server_port')
            web_port = payload.get('web_port')
            target_os = (payload.get('target_os') or 'mac').strip()
            builder = (payload.get('builder') or 'pyinstaller').strip()
            target_arch = (payload.get('target_arch') or '').strip()
            server_web_scheme = (payload.get('server_web_scheme') or 'http').strip() or 'http'
            server_web_host = (payload.get('server_web_host') or server_host).strip() or server_host
            source = (payload.get('source') or 'manual').strip() or 'manual'

            if not server_host:
                raise ValueError('server_host is required')
            if not server_port:
                raise ValueError('server_port is required')
            if not web_port:
                raise ValueError('web_port is required')

            try:
                server_port = int(server_port)
            except ValueError:
                raise ValueError('server_port must be integer')

            try:
                web_port = int(web_port)
            except ValueError:
                raise ValueError('web_port must be integer')

            result = agent_api.build_agent(
                server_host,
                server_port,
                web_port,
                target_os,
                builder,
                target_arch,
                server_web_scheme,
                server_web_host,
                source,
            )
            result['download_url'] = f'/api/agent/download/{result["file_name"]}'
            return result

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/agent/outputs')
    def list_agent_outputs():
        return responder.json_endpoint(
            lambda: agent_api.list_agent_outputs(),
            default_error_status=500,
        )

    @blueprint.delete('/api/agent/outputs/<filename>')
    def delete_agent_output(filename):
        return responder.json_endpoint(
            lambda: agent_api.delete_agent_output(filename),
            default_error_status=500,
        )

    @blueprint.get('/api/agent/download/<filename>')
    @allow_anonymous
    def download_agent(filename):
        """下载构建好的 Agent"""
        try:
            file_path = agent_api.get_built_agent_file_path(filename)
            return send_file(
                file_path,
                as_attachment=True,
                download_name=filename,
            )
        except FileNotFoundError as e:
            return responder.fail(str(e), 404)
        except Exception as e:
            return responder.map_common_error(e)

    @blueprint.get('/api/agent/platform')
    def get_agent_platform():
        return responder.json_endpoint(
            lambda: agent_api.get_server_platform(),
            default_error_status=500,
        )

    @blueprint.post('/api/agent/loader/report')
    @allow_anonymous
    def ingest_loader_report():
        return responder.json_endpoint(
            lambda: agent_api.ingest_loader_report(get_json_payload()),
            default_error_status=500,
        )

    @blueprint.delete('/api/agent/cleanup')
    def cleanup_agent_build():
        """清理构建临时文件"""

        def _execute():
            payload = get_json_payload()
            work_dir = (payload.get('work_dir') or '').strip()
            return agent_api.cleanup_agent_build(work_dir)

        return responder.json_endpoint(_execute)

    # temp
    @blueprint.post('/api/agent/bootstrap')
    @allow_anonymous
    def generate_bootstrap():
        try:
            payload = get_json_payload()
            server_host = (payload.get('server_host') or '').strip()
            server_port = payload.get('server_port')
            web_port = payload.get('web_port')

            if not server_host:
                return responder.fail('server_host is required', 400)
            if not server_port:
                return responder.fail('server_port is required', 400)
            if not web_port:
                return responder.fail('web_port is required', 400)

            try:
                server_port = int(server_port)
            except (ValueError, TypeError):
                return responder.fail('server_port must be integer', 400)

            web_host = server_host
            web_scheme = 'http'

            script_content = generate_bootstrap_script(
                server_host, server_port, web_host, web_port, web_scheme
            )

            import tempfile
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.py', delete=False, encoding='utf-8'
            ) as f:
                f.write(script_content)
                temp_path = f.name

            return send_file(
                temp_path,
                as_attachment=True,
                download_name='bootstrap.py',
                mimetype='text/x-python'
            )
        except Exception as e:
            return responder.map_common_error(e)

    return blueprint


def generate_bootstrap_script(server_host, server_port, web_host, web_port, web_scheme='http'):
    script = f'''# bootstrap.py - Cross-platform bootstrap script
# Generated by server API
import os, sys, time, shutil, zipfile, runpy, threading, json, platform, subprocess
from urllib.parse import urljoin
import requests

WEB_HOST = "{web_host}"
WEB_PORT = {web_port}
WEB_SCHEME = "{web_scheme}"
SERVER_HOST = "{server_host}"
SERVER_PORT = {server_port}

BASE_URL = f"{{WEB_SCHEME}}://{{WEB_HOST}}:{{WEB_PORT}}"
RELEASE_DIR = os.path.join(os.path.expanduser("~"), "Documents", "client_bundle", "releases")

def log(msg):
    print(f"[bootstrap] {{msg}}")

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path

def is_pythonista():
    try:
        import appex
        return True
    except ImportError:
        return sys.platform == 'ios'

def build_bundle():
    url = urljoin(BASE_URL + "/", "/api/agent/build")
    payload = {{
        "server_host": SERVER_HOST,
        "server_port": SERVER_PORT,
        "server_web_scheme": WEB_SCHEME,
        "server_web_host": WEB_HOST,
        "web_port": WEB_PORT,
        "target_os": "bundle",
        "builder": "bundle",
        "target_arch": "",
        "source": "bootstrap",
    }}
    log(f"build request: {{url}}")
    r = requests.post(url, json=payload, timeout=300)
    r.raise_for_status()
    data = r.json()
    if isinstance(data, dict) and "code" in data:
        if data.get("code") != 0:
            raise RuntimeError(data.get("message") or data)
        return data.get("data") or {{}}
    return data

def download_file(download_url, save_path):
    log(f"download: {{download_url}}")
    r = requests.get(download_url, stream=True, timeout=300)
    r.raise_for_status()
    tmp_path = save_path + ".part"
    with open(tmp_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 64):
            if chunk:
                f.write(chunk)
    if os.path.exists(save_path):
        os.remove(save_path)
    os.rename(tmp_path, save_path)
    return save_path

def unzip(zip_path, extract_dir):
    if os.path.isdir(extract_dir):
        shutil.rmtree(extract_dir)
    os.makedirs(extract_dir, exist_ok=True)
    log(f"extract: {{extract_dir}}")
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(extract_dir)
    return extract_dir

def start_ratclient(bundle_dir):
    ratclient_path = os.path.join(bundle_dir, "ratclient.py")
    if not os.path.isfile(ratclient_path):
        raise FileNotFoundError(f"ratclient.py not found: {{ratclient_path}}")

    if is_pythonista():
        log("iOS/Pythonista detected, using runpy mode")
        def runner():
            os.chdir(bundle_dir)
            if bundle_dir not in sys.path:
                sys.path.insert(0, bundle_dir)
            sys.argv = [ratclient_path]
            runpy.run_path(ratclient_path, run_name="__main__")
        t = threading.Thread(target=runner, name="ratclient-main")
        t.daemon = False
        t.start()
        return t
    else:
        log(f"Desktop detected ({{sys.platform}}), using subprocess detached mode")
        cmd = [sys.executable, ratclient_path]
        if sys.platform == 'win32':
            flags = 0x00000200 | 0x00000008
            return subprocess.Popen(
                cmd, cwd=bundle_dir,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=flags, close_fds=True
            )
        else:
            return subprocess.Popen(
                cmd, cwd=bundle_dir,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True, close_fds=True
            )

def main():
    ensure_dir(RELEASE_DIR)
    result = build_bundle()
    download_url = result.get("download_url")
    if not download_url:
        raise RuntimeError(f"missing download_url: {{result}}")
    download_url = urljoin(BASE_URL + "/", download_url)
    file_name = result.get("file_name") or os.path.basename(download_url)
    zip_path = os.path.join(RELEASE_DIR, file_name)
    base_name = os.path.splitext(file_name)[0]
    extract_dir = os.path.join(RELEASE_DIR, base_name)
    download_file(download_url, zip_path)
    unzip(zip_path, extract_dir)
    start_ratclient(extract_dir)
    log("handoff done, bootstrap exits")
    time.sleep(0.2)
    sys.exit(0)

if __name__ == "__main__":
    main()
'''
    return script