import base64
import os
import select
import signal
import struct

from core.platform.platform_identity import detect_platform_alias

if os.name != 'nt':
    import termios
import threading
import time

from core.protocol.message_types import (
    MSG_TYPE_PTY_CLOSED,
    MSG_TYPE_PTY_ERROR,
    MSG_TYPE_PTY_OPENED,
    MSG_TYPE_PTY_OUTPUT,
)


if os.name == 'nt':
    try:
        from winpty import PTY, WinptyError
    except Exception:
        PTY = None
        WinptyError = Exception


class PtyManager:
    def __init__(self, connection):
        self.connection = connection
        self._lock = threading.RLock()
        self._sessions = {}

    def open_session(self, pty_session_id: str, shell: str = '', cwd: str = '', cols: int = 120, rows: int = 32):
        with self._lock:
            if pty_session_id in self._sessions:
                self.close_session(pty_session_id)

        if os.name == 'nt':
            return self._open_session_windows(pty_session_id, shell=shell, cwd=cwd, cols=cols, rows=rows)

        if detect_platform_alias() == 'ios':
            self._send_error(pty_session_id, 'iOS is not supported')
            return False

        return self._open_session_unix(pty_session_id, shell=shell, cwd=cwd, cols=cols, rows=rows)

    def write_input(self, pty_session_id: str, data: str):
        item = self._get_session(pty_session_id)
        if not item:
            return None
        try:
            raw = base64.b64decode(str(data or '').encode(), validate=False)
        except Exception:
            raw = str(data or '').encode('utf-8', errors='replace')
        try:
            if os.name == 'nt':
                self._write_windows(item, raw)
            else:
                os.write(item['master_fd'], raw)
        except Exception as e:
            self._send_error(pty_session_id, str(e))

    def resize_session(self, pty_session_id: str, cols: int, rows: int):
        item = self._get_session(pty_session_id)
        if not item:
            return None
        cols = max(20, int(cols or item['cols'] or 120))
        rows = max(5, int(rows or item['rows'] or 32))
        item['cols'] = cols
        item['rows'] = rows
        try:
            if os.name == 'nt':
                self._resize_windows(item, cols, rows)
            else:
                self._resize_fd(item['master_fd'], cols, rows)
        except Exception:
            pass

    def close_session(self, pty_session_id: str):
        item = self._get_session(pty_session_id)
        if not item:
            return None
        with self._lock:
            item['closed'] = True

        if os.name == 'nt':
            exit_code = self._terminate_windows_process(item)
            self._finalize_session(pty_session_id, exit_code=exit_code)
            return None

        try:
            os.kill(item['pid'], signal.SIGTERM)
        except Exception:
            pass
        self._finalize_session(pty_session_id, exit_code=0)

    def _open_session_unix(self, pty_session_id: str, shell: str = '', cwd: str = '', cols: int = 120, rows: int = 32):
        pid, master_fd = os.forkpty()
        if pid == 0:
            try:
                if cwd:
                    os.chdir(cwd)
            except Exception:
                pass

            shell_path = shell or os.environ.get('SHELL') or ('/bin/zsh' if os.path.exists('/bin/zsh') else '/bin/bash')

            env = os.environ.copy()
            env.setdefault('TERM', 'xterm-256color')
            env.setdefault('COLORTERM', 'truecolor')

            # 显式启交互模式，避免 shell 退化成奇怪的半交互行为
            try:
                os.execve(shell_path, [shell_path, '-i'], env)
            except Exception:
                os.execve(shell_path, [shell_path], env)

            # os._exit(1)

        self._resize_fd(master_fd, cols, rows)
        item = {
            'pty_session_id': pty_session_id,
            'pid': pid,
            'master_fd': master_fd,
            'cols': cols,
            'rows': rows,
            'closed': False,
        }
        with self._lock:
            self._sessions[pty_session_id] = item

        self.connection.send({
            'type': MSG_TYPE_PTY_OPENED,
            'pty_session_id': pty_session_id,
        })

        threading.Thread(target=self._reader_loop_unix, args=(pty_session_id,), daemon=True).start()
        return True

    def _open_session_windows(self, pty_session_id: str, shell: str = '', cwd: str = '', cols: int = 120, rows: int = 32):
        if PTY is None:
            self._send_error(pty_session_id, 'pywinpty is not installed')
            return None

        cols = max(20, int(cols or 120))
        rows = max(5, int(rows or 32))

        try:
            pty = PTY(cols, rows)
            application_name, command = self._build_windows_command(shell)

            # 这里不改你整体架构，只把 Windows 后端换成 pywinpty。
            ok = pty.spawn(
                application_name,
                cmdline=command,
                cwd=cwd if cwd and os.path.isdir(cwd) else None,
                env=None,
            )
            if ok is False:
                raise RuntimeError('winpty spawn failed')

            item = {
                'pty_session_id': pty_session_id,
                'cols': cols,
                'rows': rows,
                'closed': False,
                'pty': pty,
                'pid': int(pty.pid or 0),
                'command': command,
            }
            with self._lock:
                self._sessions[pty_session_id] = item

            self.connection.send({
                'type': MSG_TYPE_PTY_OPENED,
                'pty_session_id': pty_session_id,
            })

            self.connection.send({
                'type': MSG_TYPE_PTY_OUTPUT,
                'pty_session_id': pty_session_id,
                'data': base64.b64encode(
                    f'[winpty] opened pid={item["pid"]} command={command}\r\n'.encode('utf-8')
                ).decode(),
            })

            threading.Thread(target=self._reader_loop_windows, args=(pty_session_id,), daemon=True).start()
            return True
        except WinptyError as e:
            self._send_error(pty_session_id, str(e))
            return None
        except Exception as e:
            self._send_error(pty_session_id, str(e))
            return None

    def _reader_loop_unix(self, pty_session_id: str):
        item = self._get_session(pty_session_id)
        if not item:
            return
        master_fd = item['master_fd']
        pid = item['pid']
        exit_code = 0
        try:
            while True:
                current = self._get_session(pty_session_id)
                if not current or current.get('closed'):
                    break
                readable, _, _ = select.select([master_fd], [], [], 0.2)
                if master_fd in readable:
                    chunk = os.read(master_fd, 4096)
                    if not chunk:
                        break
                    self.connection.send({
                        'type': MSG_TYPE_PTY_OUTPUT,
                        'pty_session_id': pty_session_id,
                        'data': base64.b64encode(chunk).decode(),
                    })
                try:
                    waited_pid, status = os.waitpid(pid, os.WNOHANG)
                    if waited_pid == pid:
                        if os.WIFEXITED(status):
                            exit_code = os.WEXITSTATUS(status)
                        elif os.WIFSIGNALED(status):
                            exit_code = 128 + os.WTERMSIG(status)
                        break
                except ChildProcessError:
                    break
        except Exception as e:
            self._send_error(pty_session_id, str(e))
        finally:
            self._finalize_session(pty_session_id, exit_code=exit_code)

    def _reader_loop_windows(self, pty_session_id: str):
        item = self._get_session(pty_session_id)
        if not item:
            return
        pty = item['pty']
        exit_code = 0

        self.connection.send({
            'type': MSG_TYPE_PTY_OUTPUT,
            'pty_session_id': pty_session_id,
            'data': base64.b64encode(b'[winpty] reader started\r\n').decode(),
        })

        try:
            while True:
                current = self._get_session(pty_session_id)
                if not current or current.get('closed'):
                    break

                try:
                    text = pty.read(blocking=False)
                except WinptyError:
                    text = ''
                except Exception:
                    text = ''

                if text:
                    self.connection.send({
                        'type': MSG_TYPE_PTY_OUTPUT,
                        'pty_session_id': pty_session_id,
                        'data': base64.b64encode(text.encode('utf-8', errors='replace')).decode(),
                    })
                    continue

                alive = False
                try:
                    alive = bool(pty.isalive())
                except Exception:
                    alive = False

                if not alive:
                    try:
                        exit_code = int(pty.get_exitstatus() or 0)
                    except Exception:
                        exit_code = 0
                    self.connection.send({
                        'type': MSG_TYPE_PTY_OUTPUT,
                        'pty_session_id': pty_session_id,
                        'data': base64.b64encode(
                            f'[winpty] process exited exit_code={exit_code}\r\n'.encode('utf-8')
                        ).decode(),
                    })
                    self._drain_windows_output(pty_session_id, pty)
                    break

                time.sleep(0.02)
        except Exception as e:
            self._send_error(pty_session_id, str(e))
        finally:
            if not exit_code:
                try:
                    exit_code = int(pty.get_exitstatus() or 0)
                except Exception:
                    exit_code = 0
            self._finalize_session(pty_session_id, exit_code=exit_code)

    def _drain_windows_output(self, pty_session_id: str, pty):
        for _ in range(20):
            try:
                text = pty.read(blocking=False)
            except Exception:
                text = ''
            if not text:
                break
            self.connection.send({
                'type': MSG_TYPE_PTY_OUTPUT,
                'pty_session_id': pty_session_id,
                'data': base64.b64encode(text.encode('utf-8', errors='replace')).decode(),
            })

    def _resize_fd(self, master_fd: int, cols: int, rows: int):
        winsz = struct.pack('HHHH', int(rows), int(cols), 0, 0)
        fcntl = __import__('fcntl')
        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsz)

    def _resize_windows(self, item: dict, cols: int, rows: int):
        pty = item.get('pty')
        if not pty:
            return None
        pty.set_size(cols, rows)
        return None

    def _write_windows(self, item: dict, raw: bytes):
        pty = item.get('pty')
        if not pty or not raw:
            return None
        text = raw.decode('utf-8', errors='replace')
        return pty.write(text)

    def _terminate_windows_process(self, item: dict):
        pty = item.get('pty')
        pid = int(item.get('pid') or 0)
        exit_code = 0

        if pty:
            try:
                pty.cancel_io()
            except Exception:
                pass

        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass

        if pty:
            for _ in range(20):
                try:
                    if not pty.isalive():
                        break
                except Exception:
                    break
                time.sleep(0.05)
            try:
                exit_code = int(pty.get_exitstatus() or 0)
            except Exception:
                exit_code = 0

        item['pty'] = None
        return exit_code

    def _finalize_session(self, pty_session_id: str, exit_code: int = 0):
        with self._lock:
            item = self._sessions.pop(pty_session_id, None)
        if not item:
            return None

        if os.name == 'nt':
            pty = item.get('pty')
            if pty:
                try:
                    pty.cancel_io()
                except Exception:
                    pass
        else:
            try:
                os.close(item['master_fd'])
            except Exception:
                pass

        self.connection.send({
            'type': MSG_TYPE_PTY_CLOSED,
            'pty_session_id': pty_session_id,
            'exit_code': int(exit_code or 0),
        })
        return None

    def _get_session(self, pty_session_id: str):
        with self._lock:
            return self._sessions.get(str(pty_session_id))

    def _send_error(self, pty_session_id: str, message: str):
        self.connection.send({
            'type': MSG_TYPE_PTY_ERROR,
            'pty_session_id': pty_session_id,
            'message': str(message or 'PTY error'),
        })

    def _build_windows_command(self, shell: str):
        shell = str(shell or '').strip()
        if shell:
            return self._parse_windows_command(shell)

        for candidate in ('cmd.exe', 'pwsh.exe', 'powershell.exe'):
            exe_path = self._which_windows(candidate)
            if exe_path:
                if candidate.lower() == 'cmd.exe':
                    return exe_path, f'"{exe_path}"'
                return exe_path, f'"{exe_path}" -NoLogo'
        return 'C:\\Windows\\System32\\cmd.exe', '"C:\\Windows\\System32\\cmd.exe"'

    def _parse_windows_command(self, shell: str):
        shell = shell.strip()
        if not shell:
            return self._build_windows_command('')

        if shell[0] == '"':
            end = shell.find('"', 1)
            if end > 0:
                exe = shell[1:end]
                rest = shell[end + 1:].strip()
                return exe, f'"{exe}" {rest}'.strip()

        parts = shell.split(None, 1)
        exe = parts[0]
        if not os.path.isabs(exe):
            resolved = self._which_windows(exe)
            if resolved:
                exe = resolved
        rest = parts[1] if len(parts) > 1 else ''
        return exe, f'"{exe}" {rest}'.strip()

    def _which_windows(self, exe_name: str):
        if os.path.isabs(exe_name) and os.path.isfile(exe_name):
            return exe_name

        paths = os.environ.get('PATH', '').split(os.pathsep)
        pathext = os.environ.get('PATHEXT', '.EXE;.BAT;.CMD').split(';')
        name_lower = exe_name.lower()
        candidates = [exe_name]
        if not any(name_lower.endswith(ext.lower()) for ext in pathext):
            candidates.extend(f'{exe_name}{ext}' for ext in pathext)

        for folder in paths:
            folder = folder.strip().strip('"')
            if not folder:
                continue
            for candidate in candidates:
                path = os.path.join(folder, candidate)
                if os.path.isfile(path):
                    return path
        return None