import json
import os
import shlex
import subprocess
import time

from client.commands.runtime.context import CommandCancelledError, CommandTimeoutError
from client.commands.runtime.interrupts import interruptible
from client.external_tools.service import ExternalToolClientService
from core.utils.decorator import desc


class CommandExternalToolMixin:
    """
    Client-side external tool lifecycle commands.

    Server renders the payload; client performs local operations:
    - check/install package
    - write config
    - start detached process
    - stop/status/list/logs/remove/clear logs
    """

    @property
    def external_tool_service(self) -> ExternalToolClientService:
        service = getattr(self, '_client_external_tool_service', None)
        if service is None:
            service = ExternalToolClientService(self)
            self._client_external_tool_service = service
        return service


    @desc('Uninstall an external tool package when no instances are running', group='runtime', suggest=False)
    @interruptible()
    def external_tool_uninstall(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self.external_tool_service.uninstall_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to uninstall external tool: {e}'

    @desc('Start an external tool instance', group='runtime', suggest=False)
    @interruptible()
    def external_tool_start(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            runtime = self.external_tool_service.build_runtime(payload)
            existing_pid = self.external_tool_service.read_pid(runtime['pid_file'])

            if self.external_tool_service.is_pid_alive(existing_pid):
                status = self.external_tool_service.status_from_payload(payload)
                status['message'] = f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} instance {payload.get("instance_id") or "default"} is already running'
                return 1, json.dumps(status, ensure_ascii=False, indent=2)

            if payload.get('install_if_needed', True):
                package_info = self.external_tool_service.download_package(payload)
                install_info = self.external_tool_service.install_if_needed(payload, package_info)
                archive_path = install_info.get('package') or package_info.get('archive_path') or ''
            else:
                archive_path = ''
                install_info = self.external_tool_service.install_status_payload(payload)
                if not install_info.get('installed'):
                    raise ValueError('Package is not installed. Please install it first.')
                install_info.update({
                    'already_installed': True,
                    'extracted': False,
                    'message': 'using existing installation',
                })
                self.external_tool_service.chmod(install_info.get('executable_path') or '')

            config_info = self.external_tool_service.write_config(payload)
            process = self.external_tool_service.start_detached(runtime)
            state_file = self.external_tool_service.write_state(payload, install_info, config_info, runtime, process)

            result = {
                'tool_id': payload.get('tool_id') or '',
                'side': payload.get('side') or 'client',
                'instance_id': payload.get('instance_id') or 'default',
                'status': 'running',
                'running': True,
                'pid': process.pid,
                'package': archive_path,
                'install': install_info,
                'config': config_info,
                'runtime': runtime,
                'state_file': state_file,
                'message': f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} instance {payload.get("instance_id") or "default"} started on client',
            }
            return 1, json.dumps(result, ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to start external tool: {e}'

    @desc('Install and run an external tool package', group='runtime', suggest=False)
    @interruptible()
    def external_tool_run(self, arg=''):
        return self.external_tool_start(arg)

    @desc('Run an external tool module once and return captured output', group='runtime', suggest=False)
    @interruptible()
    def external_tool_oneshot(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'
            if str(payload.get('execution') or payload.get('action') or '').strip().lower() not in ('oneshot',):
                raise ValueError('external tool payload execution must be oneshot')

            runtime = self.external_tool_service.build_runtime(payload)
            if payload.get('install_if_needed', True):
                package_info = self.external_tool_service.download_package(payload)
                install_info = self.external_tool_service.install_if_needed(payload, package_info)
            else:
                install_info = self.external_tool_service.install_status_payload(payload)
                if not install_info.get('installed'):
                    raise ValueError('Package is not installed. Please install it first.')
                install_info.update({
                    'already_installed': True,
                    'extracted': False,
                    'message': 'using existing installation',
                })
                self.external_tool_service.chmod(install_info.get('executable_path') or '')

            config_info = self.external_tool_service.write_config(payload)
            timeout_sec = payload.get('timeout_sec') or (payload.get('runtime') or {}).get('timeout_sec')
            run_result = self.external_tool_service.run_foreground(runtime, timeout_sec=timeout_sec)
            success = run_result.get('returncode') == 0 and not run_result.get('timed_out')

            result = {
                'tool_id': payload.get('tool_id') or '',
                'package_id': payload.get('package_id') or '',
                'module_id': payload.get('module_id') or '',
                'display_name': payload.get('display_name') or payload.get('tool_id') or '',
                'execution': 'oneshot',
                'side': payload.get('side') or 'client',
                'platform': payload.get('platform') or '',
                'arch': payload.get('arch') or '',
                'package_key': payload.get('package_key') or '',
                'run_id': payload.get('run_id') or '',
                'status': 'completed' if success else 'failed',
                'success': success,
                'running': False,
                'returncode': run_result.get('returncode'),
                'stdout': run_result.get('stdout') or '',
                'stderr': run_result.get('stderr') or '',
                'timed_out': bool(run_result.get('timed_out')),
                'started_at': run_result.get('started_at') or '',
                'finished_at': run_result.get('finished_at') or '',
                'duration_sec': run_result.get('duration_sec'),
                'install': install_info,
                'config': config_info,
                'runtime': {**runtime, 'argv': run_result.get('argv') or runtime.get('argv') or [], 'cwd': run_result.get('cwd') or runtime.get('cwd') or ''},
                'params': payload.get('params') or {},
                'message': (
                    f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} completed on client'
                    if success
                    else f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} failed on client'
                ),
            }
            return 1, json.dumps(result, ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to run external tool oneshot: {e}'

    @desc('Install an external tool package without starting it', group='runtime', suggest=False)
    @interruptible()
    def external_tool_install(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            package_info = self.external_tool_service.download_package(payload)
            install_info = self.external_tool_service.install_if_needed(payload, package_info)
            source_label = 'cached package' if install_info.get('used_cache') else 'downloaded package' if install_info.get('downloaded') else 'existing installation'
            install_info['message'] = (
                f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} already installed at {install_info.get("install_dir")}'
                if install_info.get('already_installed')
                else f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} installed from {source_label} at {install_info.get("install_dir")}'
            )

            return 1, json.dumps(install_info, ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to install external tool: {e}'

    @desc('Show external tool install status', group='runtime', suggest=False)
    @interruptible()
    def external_tool_install_status(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self.external_tool_service.install_status_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to get external tool install status: {e}'

    @desc('Clear cached external tool package archive', group='runtime', suggest=False)
    @interruptible()
    def external_tool_clear_cache(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self.external_tool_service.clear_cache_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to clear external tool package cache: {e}'

    @desc('Show external tool install statuses in one client command', group='runtime', suggest=False)
    @interruptible()
    def external_tool_install_statuses(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)

            if isinstance(payload, list):
                tools = payload
            elif isinstance(payload, dict):
                tools = payload.get('tools') or []
            else:
                return 0, 'Invalid external tool payload'

            if not isinstance(tools, list):
                return 0, 'Invalid external tool tools payload'

            items = []
            for tool_payload in tools:
                if not isinstance(tool_payload, dict):
                    continue

                try:
                    if tool_payload.get('error'):
                        raise ValueError(str(tool_payload.get('error')))
                    items.append(self.external_tool_service.install_status_payload(tool_payload))
                except Exception as e:
                    items.append({
                        'tool_id': tool_payload.get('tool_id') or '',
                        'display_name': tool_payload.get('display_name') or tool_payload.get('tool_id') or '',
                        'side': tool_payload.get('side') or 'client',
                        'installed': None,
                        'install_dir': '',
                        'skip_path': '',
                        'executable_path': '',
                        'command': '',
                        'error': str(e),
                        'message': str(e),
                    })

            return 1, json.dumps({'items': items}, ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to get external tool install statuses: {e}'

    @desc('Stop an external tool instance', group='runtime', suggest=False)
    @interruptible()
    def external_tool_stop(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            stop_result = self.external_tool_service.stop_command(payload)
            status = self.external_tool_service.status_from_payload(payload)
            status['stop_result'] = stop_result
            status['message'] = f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} instance {payload.get("instance_id") or "default"} stop requested on client'

            return 1, json.dumps(status, ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to stop external tool: {e}'

    @desc('Show external tool instance status', group='runtime', suggest=False)
    @interruptible()
    def external_tool_status(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self.external_tool_service.status_from_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to get external tool status: {e}'

    @desc('List external tool instances', group='runtime', suggest=False)
    @interruptible()
    def external_tool_list_instances(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self.external_tool_service.list_instances_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to list external tool instances: {e}'

    @desc('List all external tool instances in one command', group='runtime', suggest=False)
    @interruptible()
    def external_tool_list_instances_all(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self.external_tool_service.list_instances_all_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to list all external tool instances: {e}'

    @desc('Read external tool instance logs', group='runtime', suggest=False)
    @interruptible()
    def external_tool_logs(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self.external_tool_service.read_logs_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to read external tool logs: {e}'

    @desc('Remove stopped external tool instance runtime files', group='runtime', suggest=False)
    @interruptible()
    def external_tool_remove(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self.external_tool_service.remove_instance_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to remove external tool instance: {e}'

    @desc('Clear stopped external tool instance logs', group='runtime', suggest=False)
    @interruptible()
    def external_tool_clear_logs(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self.external_tool_service.clear_logs_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to clear external tool logs: {e}'


    #xt
    @desc('Show installed external tool executable path', group='runtime', suggest=False)
    @interruptible()
    def external_tool_which(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            status = self.external_tool_service.install_status_payload(payload)
            executable_path = status.get('executable_path') or ''

            if not status.get('installed'):
                return 0, status.get('message') or 'External tool is not installed'

            if not executable_path or not os.path.exists(executable_path):
                return 0, f'External tool executable not found: {executable_path}'

            return 1, executable_path

        except Exception as e:
            return 0, f'Failed to resolve external tool executable: {e}'

    @desc('Run an installed external tool executable with raw argv', group='runtime', suggest=False)
    @interruptible()
    def external_tool_exec(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                self._send_final_result(0, 'Invalid external tool payload')
                return

            status = self.external_tool_service.install_status_payload(payload)
            executable_path = status.get('executable_path') or ''

            if not status.get('installed'):
                self._send_final_result(0, status.get('message') or 'External tool is not installed')
                return

            if not executable_path or not os.path.exists(executable_path):
                self._send_final_result(0, f'External tool executable not found: {executable_path}')
                return

            self.external_tool_service.chmod(executable_path)

            raw_args = str(payload.get('raw_args') or '').strip()
            argv_extra = payload.get('argv_extra')
            if not isinstance(argv_extra, list):
                argv_extra = shlex.split(raw_args) if raw_args else []

            argv = [executable_path] + [str(item) for item in argv_extra]

            cli = payload.get('cli') if isinstance(payload.get('cli'), dict) else {}
            cwd = self.external_tool_service.expand_path(cli.get('cwd') or os.getcwd())
            if not os.path.isdir(cwd):
                raise FileNotFoundError(f'external tool cli cwd does not exist: {cwd}')

            timeout_sec = cli.get('timeout_sec')
            try:
                timeout_sec = float(timeout_sec)
            except Exception:
                timeout_sec = None
            if timeout_sec is not None and timeout_sec <= 0:
                timeout_sec = None

            process = subprocess.Popen(
                argv,
                shell=False,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **self._build_process_creation_kwargs()
            )
            self._register_cancel_handler(lambda: self._terminate_process(process))

            # _start_output_threads 当前签名是 _start_output_threads(process)，超时只交给 wait 层。
            self._start_output_threads(process)
            self._wait_process_with_cancel_support(process, timeout=timeout_sec)
            time.sleep(0.1)

            if process.returncode == 0:
                self._send_final_result(1, 'Command completed')
            else:
                self._send_final_result(0, f'Command exited with code {process.returncode}')

        except CommandCancelledError:
            self._send_final_result(0, 'Command cancelled')
        except (CommandTimeoutError, subprocess.TimeoutExpired):
            self._send_final_result(0, 'Command timed out and was terminated')
        except Exception as e:
            self._send_final_result(0, f'Failed to execute external tool: {e}')
