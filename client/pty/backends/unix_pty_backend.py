import os
import select
import signal
import struct
import threading

if os.name != 'nt':
    import termios
else:
    termios = None

from client.pty.session import PtySession


class UnixPtyBackend:
    """
    Unix PTY 后端。
    """

    def __init__(self, manager):
        self.manager = manager

    def open_session(self, pty_session_id: str, shell: str = '', cwd: str = '', cols: int = 120, rows: int = 32):
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

        self.resize_fd(master_fd, cols, rows)
        session = PtySession(
            pty_session_id=pty_session_id,
            backend=self,
            pid=pid,
            master_fd=master_fd,
            cols=cols,
            rows=rows,
            closed=False,
        )
        self.manager.register_session(session)
        self.manager.send_opened(pty_session_id)

        threading.Thread(target=self.reader_loop, args=(pty_session_id,), daemon=True).start()
        return True

    def write_input(self, session: PtySession, raw: bytes):
        if session.master_fd is None:
            return None
        return os.write(session.master_fd, raw)

    def resize_session(self, session: PtySession, cols: int, rows: int):
        if session.master_fd is None:
            return None
        return self.resize_fd(session.master_fd, cols, rows)

    def close_session(self, session: PtySession) -> int:
        try:
            os.kill(session.pid, signal.SIGTERM)
        except Exception:
            pass
        return 0

    def cleanup_session(self, session: PtySession):
        if session.master_fd is None:
            return None
        try:
            os.close(session.master_fd)
        except Exception:
            pass
        finally:
            session.master_fd = None
        return None

    def reader_loop(self, pty_session_id: str):
        session = self.manager.get_session(pty_session_id)
        if not session:
            return

        master_fd = session.master_fd
        pid = session.pid
        exit_code = 0

        if master_fd is None:
            self.manager.finalize_session(pty_session_id, exit_code=exit_code)
            return

        try:
            while True:
                current = self.manager.get_session(pty_session_id)
                if not current or current.closed:
                    break

                readable, _, _ = select.select([master_fd], [], [], 0.2)
                if master_fd in readable:
                    chunk = os.read(master_fd, 4096)
                    if not chunk:
                        break
                    self.manager.send_output(pty_session_id, chunk)

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
            if self.manager.get_session(pty_session_id):
                self.manager.send_error(pty_session_id, str(e))
        finally:
            self.manager.finalize_session(pty_session_id, exit_code=exit_code)

    def resize_fd(self, master_fd: int, cols: int, rows: int):
        if termios is None:
            return None

        winsz = struct.pack('HHHH', int(rows), int(cols), 0, 0)
        fcntl = __import__('fcntl')
        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsz)
        return None