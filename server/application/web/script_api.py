import base64
import json

from core.utils.script_metadata import resolve_script_params


class WebScriptApi:
    def __init__(self, command_api, script_catalog_service):
        self.command_api = command_api
        self.script_catalog_service = script_catalog_service

    def list_script_catalog(self):
        items = []
        for item in self.script_catalog_service.list_scripts() or []:
            if not isinstance(item, dict):
                continue
            script_name = str(item.get('script_name') or item.get('name') or '').strip()
            if not script_name:
                continue
            items.append({
                **item,
                'script_name': script_name,
                'display_name': str(item.get('display_name') or script_name.split('/')[-1]).strip() or script_name,
                'description': str(item.get('description') or '').strip(),
                'metadata': item.get('metadata') or {},
                'source': 'script',
            })
        return items

    def get_script_content(self, script_name: str) -> str:
        return self.script_catalog_service.get_script_content(script_name)

    def save_script_content(self, script_name: str, content: str):
        return self.script_catalog_service.save_script(script_name, content)

    def upload_script(self, file_storage, directory: str = ''):
        return self.script_catalog_service.upload_script(file_storage, directory=directory)

    def delete_script(self, script_name: str):
        return self.script_catalog_service.delete_script(script_name)

    def _encode_payload_arg(self, payload: dict) -> str:
        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
        return f'__json__:{encoded}'

    def run_script(self, client_id: str, script_name: str, params=None, tab_id: str = ''):
        normalized_script_name = str(script_name or '').strip()
        if not normalized_script_name:
            raise ValueError('script_name is required')
        metadata = {}
        for item in self.script_catalog_service.list_scripts() or []:
            if str(item.get('script_name') or '').strip() == normalized_script_name:
                metadata = item.get('metadata') or {}
                break
        normalized_params = resolve_script_params(metadata, params if isinstance(params, dict) else {})
        payload = {
            'script_name': normalized_script_name,
            'params': normalized_params,
        }
        return self.command_api.submit_web_command(
            client_id,
            f'run_script {self._encode_payload_arg(payload)}',
            tab_id=tab_id,
        )
