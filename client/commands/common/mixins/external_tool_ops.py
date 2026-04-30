import json
import os
import shlex
import subprocess

from client.commands.runtime.interrupts import interruptible
from core.utils.client_util import safe_extract_zip_file
from core.utils.decorator import desc

import sys
import tempfile
from types import SimpleNamespace


class CommandExternalToolMixin:
    """
    External tool runtime command.

    Payload is prepared by the server from external tool meta.
    The client only performs deterministic operations:
    download zip, extract if needed, write rendered config, chmod executable, run detached.
    """

    DOWNLOAD_TIMEOUT = (15, 600)
    DOWNLOAD_CHUNK_SIZE = 64 * 1024

    def _external_tool_expand_path(self, path: str) -> str:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(str(path or '').strip())))

    def _external_tool_render_path_list(self, values):
        if isinstance(values, str):
            return shlex.split(values)
        if isinstance(values, list):
            return [str(item) for item in values]
        return []

    def _external_tool_chmod(self, path: str):
        if not path or os.name == 'nt' or not os.path.exists(path):
            return
        mode = os.stat(path).st_mode
        os.chmod(path, mode | 0o111)

    def _external_tool_download_package(self, payload: dict) -> str:
        package = payload.get('package') or {}
        filename = os.path.basename(str(package.get('filename') or '').strip())
        download_url = str(package.get('download_url') or '').strip()
        if not filename:
            raise ValueError('package.filename is required')
        if not download_url:
            raise ValueError('package.download_url is required')

        cache_dir = self._external_tool_expand_path('~/.ops/external_tools/packages')
        os.makedirs(cache_dir, exist_ok=True)
        archive_path = os.path.join(cache_dir, filename)
        if os.path.isfile(archive_path) and os.path.getsize(archive_path) > 0:
            return archive_path

        self.client_api.download_file(
            download_url,
            archive_path,
            timeout=self.DOWNLOAD_TIMEOUT,
            chunk_size=self.DOWNLOAD_CHUNK_SIZE,
            ensure_not_interrupted=self._ensure_not_interrupted,
        )
        return archive_path

    def _external_tool_install_if_needed(self, payload: dict, archive_path: str) -> dict:
        install = payload.get('install') or {}
        install_dir = self._external_tool_expand_path(install.get('install_dir') or '~/.ops/external_tools/installed/unknown')
        skip_if_exists = self._external_tool_expand_path(install.get('skip_if_exists') or install_dir)
        already_installed = os.path.exists(skip_if_exists)
        extracted = False

        if not already_installed:
            os.makedirs(install_dir, exist_ok=True)
            safe_extract_zip_file(archive_path, install_dir)
            extracted = True

        package = payload.get('package') or {}
        executable_rel_path = str(package.get('executable_rel_path') or '').strip()
        executable_path = self._external_tool_expand_path(os.path.join(install_dir, executable_rel_path)) if executable_rel_path else skip_if_exists
        self._external_tool_chmod(executable_path)

        return {
            'install_dir': install_dir,
            'skip_path': skip_if_exists,
            'already_installed': already_installed,
            'extracted': extracted,
            'executable_path': executable_path,
        }

    def _external_tool_write_config(self, payload: dict) -> dict:
        config = payload.get('config') or {}
        target = str(config.get('target') or '').strip()
        if not target:
            return {}
        content = str(config.get('content') or '')
        target_path = self._external_tool_expand_path(target)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, 'w', encoding='utf-8') as file_obj:
            file_obj.write(content)
        return {'target': target_path, 'size': os.path.getsize(target_path)}

    def _external_tool_build_runtime(self, payload: dict) -> dict:
        runtime = payload.get('runtime') or {}
        argv = self._external_tool_render_path_list(runtime.get('argv') or [])
        if not argv:
            raise ValueError('runtime.argv is required')
        argv = [
            self._external_tool_expand_path(item) if index == 0 or '/' in item or '\\' in item else item
            for index, item in enumerate(argv)
        ]
        cwd = self._external_tool_expand_path(runtime.get('cwd') or os.getcwd())
        stdout = self._external_tool_expand_path(runtime.get('stdout') or '~/.ops/external_tools/runtime/stdout.log')
        stderr = runtime.get('stderr') or 'stdout'
        if stderr != 'stdout':
            stderr = self._external_tool_expand_path(stderr)
        pid_file = self._external_tool_expand_path(runtime.get('pid_file') or '~/.ops/external_tools/runtime/tool.pid')
        return {
            'argv': argv,
            'cwd': cwd,
            'stdout': stdout,
            'stderr': stderr,
            'pid_file': pid_file,
        }

    def _external_tool_start_detached(self, runtime: dict) -> SimpleNamespace:
        """
        Start the external executable through a short-lived launcher process.

        This prevents the real frpc process from remaining a direct child of the
        client agent process.
        """
        os.makedirs(runtime['cwd'], exist_ok=True)
        os.makedirs(os.path.dirname(runtime['stdout']), exist_ok=True)
        os.makedirs(os.path.dirname(runtime['pid_file']), exist_ok=True)

        if runtime.get('stderr') not in ('', None, 'stdout'):
            os.makedirs(os.path.dirname(runtime['stderr']), exist_ok=True)

        launch_spec = {
            'argv': runtime['argv'],
            'cwd': runtime['cwd'],
            'stdout': runtime['stdout'],
            'stderr': runtime.get('stderr') or 'stdout',
            'pid_file': runtime['pid_file'],
        }

        spec_fd, spec_path = tempfile.mkstemp(
            prefix='external-tool-launch-',
            suffix='.json',
            dir=os.path.dirname(runtime['pid_file']),
        )

        try:
            with os.fdopen(spec_fd, 'w', encoding='utf-8') as file_obj:
                json.dump(launch_spec, file_obj, ensure_ascii=False)

            launcher_code = r'''
import json
import os
import subprocess
import sys

spec_path = sys.argv[1]

with open(spec_path, 'r', encoding='utf-8') as file_obj:
    spec = json.load(file_obj)

stdout_file = open(spec['stdout'], 'ab')
stderr_file = None

try:
    stderr_value = spec.get('stderr') or 'stdout'
    if stderr_value == 'stdout':
        stderr_target = subprocess.STDOUT
    else:
        stderr_file = open(stderr_value, 'ab')
        stderr_target = stderr_file

    kwargs = {
        'cwd': spec['cwd'],
        'stdin': subprocess.DEVNULL,
        'stdout': stdout_file,
        'stderr': stderr_target,
        'close_fds': True,
        'shell': False,
    }

    if os.name == 'nt':
        flags = 0
        flags |= getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
        flags |= getattr(subprocess, 'DETACHED_PROCESS', 0)
        process = subprocess.Popen(spec['argv'], creationflags=flags, **kwargs)
    else:
        process = subprocess.Popen(spec['argv'], start_new_session=True, **kwargs)

    with open(spec['pid_file'], 'w', encoding='utf-8') as pid_obj:
        pid_obj.write(str(process.pid))

    print(process.pid)

finally:
    stdout_file.close()
    if stderr_file is not None:
        stderr_file.close()
'''

            completed = subprocess.run(
                [sys.executable, '-c', launcher_code, spec_path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                close_fds=True,
            )

            if completed.returncode != 0:
                raise RuntimeError(
                    (completed.stderr or completed.stdout or 'external tool client launcher failed').strip()
                )

            pid_text = (completed.stdout or '').strip().splitlines()[-1]
            return SimpleNamespace(pid=int(pid_text))

        finally:
            try:
                os.unlink(spec_path)
            except OSError:
                pass

    # def _external_tool_start_detached(self, runtime: dict) -> subprocess.Popen:
    #     os.makedirs(runtime['cwd'], exist_ok=True)
    #     os.makedirs(os.path.dirname(runtime['stdout']), exist_ok=True)
    #     os.makedirs(os.path.dirname(runtime['pid_file']), exist_ok=True)
    #
    #     stdout_file = open(runtime['stdout'], 'ab')
    #     stderr_file = None
    #     stderr_target = subprocess.STDOUT
    #     if runtime.get('stderr') != 'stdout':
    #         os.makedirs(os.path.dirname(runtime['stderr']), exist_ok=True)
    #         stderr_file = open(runtime['stderr'], 'ab')
    #         stderr_target = stderr_file
    #
    #     popen_kwargs = {
    #         'cwd': runtime['cwd'],
    #         'stdin': subprocess.DEVNULL,
    #         'stdout': stdout_file,
    #         'stderr': stderr_target,
    #         'close_fds': True,
    #         'shell': False,
    #     }
    #     try:
    #         if os.name == 'nt':
    #             flags = 0
    #             flags |= getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
    #             flags |= getattr(subprocess, 'DETACHED_PROCESS', 0)
    #             process = subprocess.Popen(runtime['argv'], creationflags=flags, **popen_kwargs)
    #         else:
    #             process = subprocess.Popen(runtime['argv'], start_new_session=True, **popen_kwargs)
    #     finally:
    #         stdout_file.close()
    #         if stderr_file is not None:
    #             stderr_file.close()
    #
    #     with open(runtime['pid_file'], 'w', encoding='utf-8') as file_obj:
    #         file_obj.write(str(process.pid))
    #     return process

    # def _external_tool_write_state(self, payload: dict, install_info: dict, runtime: dict, process: subprocess.Popen) -> str:
    def _external_tool_write_state(self, payload: dict, install_info: dict, runtime: dict, process: SimpleNamespace) -> str:
        state_file = os.path.join(os.path.dirname(runtime['pid_file']), 'state.json')
        state = {
            'tool_id': payload.get('tool_id') or '',
            'display_name': payload.get('display_name') or payload.get('tool_id') or '',
            'version': payload.get('version') or '',
            'side': payload.get('side') or 'client',
            'pid': process.pid,
            'install_dir': install_info.get('install_dir') or '',
            'argv': runtime.get('argv') or [],
            'cwd': runtime.get('cwd') or '',
            'stdout': runtime.get('stdout') or '',
            'stderr': runtime.get('stderr') or '',
            'pid_file': runtime.get('pid_file') or '',
        }
        with open(state_file, 'w', encoding='utf-8') as file_obj:
            json.dump(state, file_obj, ensure_ascii=False, indent=2)
        return state_file

    @desc('Install and run an external tool package', group='runtime', suggest=False)
    @interruptible()
    def external_tool_run(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            archive_path = self._external_tool_download_package(payload)
            install_info = self._external_tool_install_if_needed(payload, archive_path)
            config_info = self._external_tool_write_config(payload)
            runtime = self._external_tool_build_runtime(payload)
            process = self._external_tool_start_detached(runtime)
            state_file = self._external_tool_write_state(payload, install_info, runtime, process)

            result = {
                'tool_id': payload.get('tool_id') or '',
                'side': payload.get('side') or 'client',
                'pid': process.pid,
                'package': archive_path,
                'install': install_info,
                'config': config_info,
                'runtime': runtime,
                'state_file': state_file,
                'message': f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} started on client',
            }
            return 1, json.dumps(result, ensure_ascii=False, indent=2)
        except Exception as e:
            return 0, f'Failed to run external tool: {e}'
