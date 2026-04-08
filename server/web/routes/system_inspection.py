from flask import Blueprint

from server.web.api_response import WebApiResponder


def create_system_inspection_blueprint(server_instance):
    blueprint = Blueprint('system_inspection', __name__)
    web_service = server_instance.web_service
    system_api = web_service.system_api
    responder = WebApiResponder()

    @blueprint.get('/api/connections/<client_id>/system-paths')
    def get_system_paths(client_id):
        """获取客户端系统路径"""
        return responder.json_endpoint(
            lambda: system_api.get_system_paths(client_id),
            default_error_status=500,
        )

    @blueprint.get('/api/connections/<client_id>/processes')
    def list_processes(client_id):
        """获取客户端进程列表"""
        return responder.json_endpoint(
            lambda: system_api.list_processes(client_id),
            default_error_status=500,
        )

    @blueprint.get('/api/connections/<client_id>/processes/<int:pid>/detail')
    def get_process_detail(client_id, pid):
        """获取客户端进程详情"""
        return responder.json_endpoint(
            lambda: system_api.get_process_detail(client_id, pid),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/processes/<int:pid>/kill')
    def kill_process(client_id, pid):
        """终止进程"""
        return responder.json_endpoint(
            lambda: system_api.kill_process(client_id, pid),
            default_error_status=500,
        )

    @blueprint.get('/api/connections/<client_id>/apps')
    def list_apps(client_id):
        """获取客户端运行的应用列表"""
        return responder.json_endpoint(
            lambda: system_api.list_apps(client_id),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/apps/<int:pid>/kill')
    def kill_app(client_id, pid):
        """终止应用"""
        return responder.json_endpoint(
            lambda: system_api.kill_app(client_id, pid),
            default_error_status=500,
        )

    return blueprint