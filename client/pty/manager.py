import base64
import os
import select
import signal
import struct
import termios
import threading
import time

from core.protocol.message_types import (
    MSG_TYPE_PTY_CLOSED,
    MSG_TYPE_PTY_ERROR,
    MSG_TYPE_PTY_OPENED,
    MSG_TYPE_PTY_OUTPUT,
)


class PtyManager:
    def __init__(self, connection):
        self.connection = connection
        self._lock = threading.RLock()
        self._sessions = {}

    def open_session(self, pty_session_id: str, shell: str = '', cwd: str = '', cols: int = 120, rows: int = 32):
        if os.name == 'nt':
            self._send_error(pty_session_id, 'PTY is not supported on Windows in this build')
            return None

        with self._lock:
            if pty_session_id in self._sessions:
                self.close_session(pty_session_id)

        pid, master_fd = os.forkpty()
        if pid == 0:
            try:
                if cwd:
                    os.chdir(cwd)
            except Exception:
                pass
            shell_path = shell or os.environ.get('SHELL') or ('/bin/zsh' if os.path.exists('/bin/zsh') else '/bin/bash')
            os.execv(shell_path, [shell_path])
            os._exit(1)

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

        threading.Thread(target=self._reader_loop, args=(pty_session_id,), daemon=True).start()
        return True

    def write_input(self, pty_session_id: str, data: str):
        item = self._get_session(pty_session_id)
        if not item:
            return None
        try:
            raw = base64.b64decode(str(data or '').encode(), validate=False)
        except Exception:
            raw = str(data or '').encode('utf-8', errors='replace')
        try:
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
            self._resize_fd(item['master_fd'], cols, rows)
        except Exception:
            pass

    def close_session(self, pty_session_id: str):
        item = self._get_session(pty_session_id)
        if not item:
            return None
        with self._lock:
            item['closed'] = True
        try:
            os.kill(item['pid'], signal.SIGTERM)
        except Exception:
            pass
        try:
            os.close(item['master_fd'])
        except Exception:
            pass
        with self._lock:
            self._sessions.pop(pty_session_id, None)
        self.connection.send({
            'type': MSG_TYPE_PTY_CLOSED,
            'pty_session_id': pty_session_id,
            'exit_code': 0,
        })

    def _reader_loop(self, pty_session_id: str):
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
            with self._lock:
                self._sessions.pop(pty_session_id, None)
            try:
                os.close(master_fd)
            except Exception:
                pass
            self.connection.send({
                'type': MSG_TYPE_PTY_CLOSED,
                'pty_session_id': pty_session_id,
                'exit_code': exit_code,
            })

    def _resize_fd(self, master_fd: int, cols: int, rows: int):
        winsz = struct.pack('HHHH', int(rows), int(cols), 0, 0)
        fcntl = __import__('fcntl')
        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsz)

    def _get_session(self, pty_session_id: str):
        with self._lock:
            return self._sessions.get(str(pty_session_id))

    def _send_error(self, pty_session_id: str, message: str):
        self.connection.send({
            'type': MSG_TYPE_PTY_ERROR,
            'pty_session_id': pty_session_id,
            'message': str(message or 'PTY error'),
        })
