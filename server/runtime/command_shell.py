import socket
import sys
import time

from core.utils.formatting import print_table
from core.utils.parsing import parse
from core.utils.server_util import *
from server.application.command.command_execution_event import CommandExecutionEvent
from server.application.command.command_execution_pipeline import CommandExecutionPipeline
from server.application.execution.execution_context import ExecutionContext
from server.connection.client_session import ClientSession


class ServerCommandShell:
    def __init__(self, server):
        self.server = server
        self.command_execution_pipeline = CommandExecutionPipeline(
            command_history_orchestrator=server.command_history_orchestrator,
        )

    def list_connections(self):
        """
        显示连接列表
        """
        connection_list = self.server.connections.all()
        if not connection_list:
            print("No active sessions")
            return

        headers = ['ID', 'Address', 'OS', 'OS Version', 'Hostname', 'Integrity']
        data = [
            [
                str(i),
                session.session_info.addr or 'N/A',
                session.session_info.os_type,
                session.session_info.os_ver,
                session.session_info.hostname,
                session.session_info.integrity
            ]
            for i, session in enumerate(connection_list)
        ]
        print_table(headers, data)

    def get_last_connection(self) -> ClientSession:
        """
        获取最新连接
        """
        try:
            return self.server.connections.last()
        except Exception:
            raise Exception('No active session available')

    def get_target_connection(self, target: str) -> ClientSession:
        """
        根据索引或 client_id 获取连接
        """
        try:
            return self.server.connections.find(target)
        except Exception:
            raise Exception('Not a valid selection')

    def _clear_screen(self):
        """
        清屏，不依赖外部 clear/cls 命令
        """
        sys.stdout.write('\033[2J\033[H')
        sys.stdout.flush()

    def _print_unread_messages(self, session: ClientSession):
        """
        输出连接的未读消息

        说明：
        - 当前这份基线里 runtime 可能没有 unread_message_manager
        - 为避免进入交互直接崩，这里做安全降级
        """
        unread_manager = getattr(session.runtime, 'unread_message_manager', None)
        if unread_manager is None:
            return

        try:
            unread = unread_manager.drain()
        except Exception:
            return

        for item in unread:
            level = item.get('level', 'info')
            text = item.get('text', '')
            if level == 'error':
                print_error(text)
            else:
                print(text)

    def _emit_cli_event(self, event: CommandExecutionEvent):
        if event.event_type == CommandExecutionEvent.STARTED:
            return
        if event.event_type == CommandExecutionEvent.COMPLETED:
            return
        if event.event_type == CommandExecutionEvent.CANCELLED and event.payload.get('terminal'):
            return
        if event.event_type == CommandExecutionEvent.CHUNK:
            write(event.status, event.text)
            return
        if event.event_type == CommandExecutionEvent.ERROR:
            write(0, event.text)
            return
        if event.event_type == CommandExecutionEvent.CANCELLED:
            write(0, event.text or 'cancelled')
            return
        if event.event_type == CommandExecutionEvent.PROGRESS and event.text:
            write(1, event.text)

    def _execute_interactive_command(self, session: ClientSession, command_executor, cmd: str):
        """
        执行交互命令并输出结果。
        """
        entry_id = self.server.command_history_orchestrator.begin_execution(
            session,
            cmd,
            source='cli',
        )

        context = ExecutionContext.from_session(
            session,
            cmd,
            source='cli',
            task_type='command',
            history_entry_id=entry_id,
        )
        final_ok = True

        for event in self.command_execution_pipeline.iter_events(
                context,
                command_executor,
                cwd_end_provider=lambda: session.session_info.cwd,
                finalize_history=True,
                swallow_exception=False,
        ):
            if event.event_type == CommandExecutionEvent.COMPLETED:
                final_ok = bool(event.ok)
                continue

            if event.event_type == CommandExecutionEvent.CANCELLED and event.payload.get('terminal'):
                final_ok = False
                continue

            self._emit_cli_event(event)

        return final_ok

    def _open_latest_from_interactive(self, current_session: ClientSession):
        """
        交互态快速切到最新连接
        - 如果当前已经是最新连接：留在当前会话，不退出
        - 如果有更新连接：切过去，并结束当前会话
        """
        latest_session = self.get_last_connection()
        if latest_session is current_session:
            return 'stay'

        self.open_connection(latest_session)
        return 'switched'

    def open_connection(self, session: ClientSession):
        """
        与会话交互
        """
        print('[+] Connected to {}'.format(session.address))
        self._print_unread_messages(session)
        session.context.is_interactive = True

        command_executor = self.server.web_service.command_executor_factory.create(
            session,
            use_foreground_guard=True,
            foreground_source='cli'
        )

        try:
            while 1:
                try:
                    cmd = colored_input('{}> '.format(session.session_info.cwd))
                    cmd = (cmd or '').strip()

                    if not cmd:
                        continue

                    if cmd in ['clear', 'cls']:
                        self._clear_screen()
                        continue

                    if cmd in ['bg', 'background', 'exit', 'quit']:
                        return

                    if cmd == 'q':
                        action = self._open_latest_from_interactive(session)
                        if action == 'stay':
                            continue
                        if action == 'switched':
                            return
                        continue

                    if cmd in ['kill', 'reset']:
                        session.send_command(cmd)
                        return

                    self._execute_interactive_command(session, command_executor, cmd)
                except Exception as e:
                    print_error(f'{e.__class__.__name__}: {e}')
        except socket.error:
            print_error('[-] Connection closed')
        except KeyboardInterrupt:
            print(Colors.RESET)
            time.sleep(0.1)
        except Exception as e:
            print_error(f'{e.__class__.__name__}: {e}')
        finally:
            session.context.is_interactive = False

    def _handle_console_command(self, cmd: str):
        """
        处理主控台命令
        """
        name, arg = parse(cmd)

        if cmd in ['l', 'ls', 'list']:
            self.list_connections()
            return

        if cmd == 'q':
            self.open_connection(self.get_last_connection())
            return

        if name in ['i', 's', 'select']:
            target = arg.strip() if arg else ''
            if target:
                self.open_connection(self.get_target_connection(target))
            else:
                self.open_connection(self.get_last_connection())
            return

        if cmd in ['quit', 'exit']:
            self.server.socket.close()
            sys.exit(0)

        if cmd in ['cls', 'clear']:
            self._clear_screen()
            return

        if name == 'cd':
            print(cd(arg))
            return

        try:
            self.open_connection(self.get_target_connection(cmd))
            return
        except Exception:
            raise Exception('Command not recognized')

    def serve_console_loop(self):
        """
        主控台循环
        """
        while 1:
            try:
                cmd = colored_input('server> ')
                cmd = (cmd or '').strip()

                if not cmd:
                    continue

                self._handle_console_command(cmd)
            except KeyboardInterrupt:
                print(Colors.RESET)
                self.server.socket.close()
                sys.exit(0)
            except Exception as e:
                write(0, f'[-] {type(e).__name__}: {e}')
            finally:
                print()