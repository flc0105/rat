import os
import signal
import threading
import time

from client.pty.session import PtySession

if os.name == 'nt':
    try:
        from winpty import PTY, WinptyError
    except Exception:
        PTY = None
        WinptyError = Exception
else:
    PTY = None
    WinptyError = Exception


class WindowsPtyBackend:
    """
    Windows PTY 后端。
    """

    def __init__(self, manager):
        self.manager = manager

    def open_session(self, pty_session_id: str, shell: str = '', cwd: str = '', cols: int = 120, rows: int = 32):
        if PTY is None:
            self.manager.send_error(pty_session_id, 'pywinpty is not installed')
            return None

        cols = max(20, int(cols or 120))
        rows = max(5, int(rows or 32))

        try:
            pty = PTY(cols, rows)
            application_name, command = self.build_windows_command(shell)

            # 这里不改你整体架构，只把 Windows 后端换成 pywinpty。
            ok = pty.spawn(
                application_name,
                cmdline=command,
                cwd=cwd if cwd and os.path.isdir(cwd) else None,
                env=None,
            )
            if ok is False:
                raise RuntimeError('winpty spawn failed')

            session = PtySession(
                pty_session_id=pty_session_id,
                backend=self,
                cols=cols,
                rows=rows,
                closed=False,
                pty=pty,
                pid=int(pty.pid or 0),
                command=command,
            )
            self.manager.register_session(session)
            self.manager.send_opened(pty_session_id)
            self.manager.send_output(
                pty_session_id,
                f'[winpty] opened pid={session.pid} command={command}\r\n'.encode('utf-8')
            )

            threading.Thread(target=self.reader_loop, args=(pty_session_id,), daemon=True).start()
            return True
        except WinptyError as e:
            self.manager.send_error(pty_session_id, str(e))
            return None
        except Exception as e:
            self.manager.send_error(pty_session_id, str(e))
            return None

    def write_input(self, session: PtySession, raw: bytes):
        pty = session.pty
        if not pty or not raw:
            return None
        text = raw.decode('utf-8', errors='replace')
        return pty.write(text)

    def resize_session(self, session: PtySession, cols: int, rows: int):
        pty = session.pty
        if not pty:
            return None
        pty.set_size(cols, rows)
        return None

    def close_session(self, session: PtySession) -> int:
        pty = session.pty
        pid = int(session.pid or 0)
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

        session.pty = None
        return exit_code

    def cleanup_session(self, session: PtySession):
        pty = session.pty
        if pty:
            try:
                pty.cancel_io()
            except Exception:
                pass
        session.pty = None
        return None

    def reader_loop(self, pty_session_id: str):
        session = self.manager.get_session(pty_session_id)
        if not session:
            return

        pty = session.pty
        exit_code = 0

        self.manager.send_output(pty_session_id, b'[winpty] reader started\r\n')

        try:
            while True:
                current = self.manager.get_session(pty_session_id)
                if not current or current.closed:
                    break

                try:
                    text = pty.read(blocking=False)
                except WinptyError:
                    text = ''
                except Exception:
                    text = ''

                if text:
                    self.manager.send_output(pty_session_id, text.encode('utf-8', errors='replace'))
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
                    self.manager.send_output(
                        pty_session_id,
                        f'[winpty] process exited exit_code={exit_code}\r\n'.encode('utf-8')
                    )
                    self.drain_output(pty_session_id, pty)
                    break

                time.sleep(0.02)
        except Exception as e:
            if self.manager.get_session(pty_session_id):
                self.manager.send_error(pty_session_id, str(e))
        finally:
            if not exit_code:
                try:
                    exit_code = int(pty.get_exitstatus() or 0)
                except Exception:
                    exit_code = 0
            self.manager.finalize_session(pty_session_id, exit_code=exit_code)

    def drain_output(self, pty_session_id: str, pty):
        for _ in range(20):
            try:
                text = pty.read(blocking=False)
            except Exception:
                text = ''
            if not text:
                break
            self.manager.send_output(pty_session_id, text.encode('utf-8', errors='replace'))

    def build_windows_command(self, shell: str):
        shell = str(shell or '').strip()
        if shell:
            return self.parse_windows_command(shell)

        for candidate in ('cmd.exe', 'pwsh.exe', 'powershell.exe'):
            exe_path = self.which_windows(candidate)
            if exe_path:
                if candidate.lower() == 'cmd.exe':
                    return exe_path, f'"{exe_path}"'
                return exe_path, f'"{exe_path}" -NoLogo'
        return 'C:\\Windows\\System32\\cmd.exe', '"C:\\Windows\\System32\\cmd.exe"'

    def parse_windows_command(self, shell: str):
        shell = shell.strip()
        if not shell:
            return self.build_windows_command('')

        if shell[0] == '"':
            end = shell.find('"', 1)
            if end > 0:
                exe = shell[1:end]
                rest = shell[end + 1:].strip()
                return exe, f'"{exe}" {rest}'.strip()

        parts = shell.split(None, 1)
        exe = parts[0]
        if not os.path.isabs(exe):
            resolved = self.which_windows(exe)
            if resolved:
                exe = resolved
        rest = parts[1] if len(parts) > 1 else ''
        return exe, f'"{exe}" {rest}'.strip()

    def which_windows(self, exe_name: str):
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