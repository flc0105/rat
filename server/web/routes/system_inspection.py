import json

from flask import Blueprint

from server.web.api_response import WebApiResponder


def create_system_inspection_blueprint(server_instance):
    blueprint = Blueprint('system_inspection', __name__)
    responder = WebApiResponder()

    @blueprint.get('/api/connections/<client_id>/system-paths')
    def get_system_paths(client_id):
        """获取客户端系统路径"""

        def _execute():
            session = server_instance.get_target_connection_by_client_id(client_id)
            # 从已存储的 info 中获取
            system_paths = session.info.get('system_paths', {})
            return system_paths

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/connections/<client_id>/processes')
    def list_processes(client_id):
        """获取客户端进程列表"""

        def _execute():
            session = server_instance.get_target_connection_by_client_id(client_id)
            result_text = server_instance.web_service.remote_execution_service.run_foreground_text_command(
                client_id,
                'list_processes',
                task_type='process',
                source='web_process',
            )

            try:
                processes = json.loads(result_text)
                return processes
            except Exception:
                return []

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/connections/<client_id>/processes/<int:pid>/detail')
    def get_process_detail(client_id, pid):
        """获取客户端进程详情"""

        def _execute():
            session = server_instance.get_target_connection_by_client_id(client_id)
            result_text = server_instance.web_service.remote_execution_service.run_foreground_text_command(
                client_id,
                f'get_process_detail {pid}',
                task_type='process',
                source='web_process',
            )

            try:
                return json.loads(result_text)
            except Exception:
                return {}

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/processes/<int:pid>/kill')
    def kill_process(client_id, pid):
        """终止进程"""

        def _execute():
            session = server_instance.get_target_connection_by_client_id(client_id)
            result_text = server_instance.web_service.remote_execution_service.run_foreground_text_command(
                client_id,
                f'kill_process {pid}',
                task_type='process',
                source='web_process',
            )

            return {'message': result_text}

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/connections/<client_id>/apps')
    def list_apps(client_id):
        """获取客户端运行的应用列表"""

        def _execute():
            session = server_instance.get_target_connection_by_client_id(client_id)
            result_text = server_instance.web_service.remote_execution_service.run_foreground_text_command(
                client_id,
                'list_apps',
                task_type='process',
                source='web_process',
            )
            try:
                apps = json.loads(result_text)
                return apps
            except Exception:
                return []

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/apps/<int:pid>/kill')
    def kill_app(client_id, pid):
        """终止应用"""

        def _execute():
            session = server_instance.get_target_connection_by_client_id(client_id)
            result_text = server_instance.web_service.remote_execution_service.run_foreground_text_command(
                client_id,
                f'kill_process {pid}',
                task_type='process',
                source='web_process',
            )
            return {'message': result_text}

        return responder.json_endpoint(_execute, default_error_status=500)

    return blueprint
