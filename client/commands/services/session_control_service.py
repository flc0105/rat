# import os
# import subprocess
# import time
#
# from core.utils.client_util import get_executable_path, reset
#
#
# class SessionControlService:
#     def __init__(self, socket=None):
#         self.socket = socket
#
#
#     def _close_socket_quietly(self):
#         try:
#             if self.socket is not None:
#                 self.socket.close()
#         except Exception:
#             pass
#
#
#     def kill_current_session(self):
#         self._close_socket_quietly()
#         time.sleep(0.2)
#         os._exit(0)
#
#
#     def reset_current_session(self):
#         reset(self.socket)
#
#
#     def execute_control_command(self, command: str):
#         command_text = str(command or '').strip().lower()
#
#         if command_text == 'kill':
#             self.kill_current_session()
#
#         if command_text == 'reset':
#             self.reset_current_session()
#
#         raise ValueError(f'Unsupported control command: {command_text}')