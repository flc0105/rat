import os

from flask import Blueprint, request, send_file

from server.web.api_response import WebApiResponder
from server.web.request_parsers import get_json_payload


def create_agent_blueprint(server_instance):
    blueprint = Blueprint('agent', __name__)
    web_service = server_instance.web_service
    responder = WebApiResponder()

    @blueprint.post('/api/agent/build')
    def build_agent():
        """构建 Agent"""

        def _execute():
            payload = get_json_payload()
            server_host = (payload.get('server_host') or '').strip()
            server_port = payload.get('server_port')
            web_port = payload.get('web_port')
            target_os = (payload.get('target_os') or 'mac').strip()
            builder = (payload.get('builder') or 'pyinstaller').strip()
            target_arch = (payload.get('target_arch') or 'auto').strip()

            if not server_host:
                raise ValueError('server_host is required')
            if not server_port:
                raise ValueError('server_port is required')

            try:
                server_port = int(server_port)
            except ValueError:
                raise ValueError('server_port must be integer')

            return web_service.build_agent(
                server_host,
                server_port,
                web_port,
                target_os,
                builder,
                target_arch,
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/agent/download/<filename>')
    def download_agent(filename):
        """下载构建好的 Agent"""
        try:
            file_path = os.path.join(web_service.agent_builder.output_dir, filename)
            if not os.path.isfile(file_path):
                return responder.fail('File not found', 404)

            return send_file(
                file_path,
                as_attachment=True,
                download_name=filename
            )
        except Exception as e:
            return responder.map_common_error(e)

    @blueprint.delete('/api/agent/cleanup')
    def cleanup_agent_build():
        """清理构建临时文件"""

        def _execute():
            payload = get_json_payload()
            work_dir = (payload.get('work_dir') or '').strip()
            if work_dir:
                web_service.cleanup_agent_build(work_dir)
            return {'cleaned': True}

        return responder.json_endpoint(_execute)

    return blueprint