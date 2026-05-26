import builtins
from urllib.parse import quote

from client.runtime.sdk import context


WORKSPACE_READ_GRANT = 'workspace:read'


class ScriptSdkWorkspaceError(RuntimeError):
    """Script SDK workspace 统一异常。"""
    pass


def _safe_text(value) -> str:
    return '' if value is None else str(value).strip()


def _missing_grant_message() -> str:
    return (
        f'Workspace access requires script grant: {WORKSPACE_READ_GRANT}. '
        f'Add SCRIPT_METADATA["api_grants"] = ["{WORKSPACE_READ_GRANT}"] to this script.'
    )


def _current_client_id() -> str:
    client_id = context.client_id()
    if not client_id:
        raise ScriptSdkWorkspaceError('current client_id is empty')
    return client_id


def _request_workspace() -> dict:
    try:
        from client.http.client_api import ClientApiClient, ClientApiError

        client_id = quote(_current_client_id(), safe='')
        data = ClientApiClient().get_data(f'/api/connections/{client_id}/pinned_paths', timeout=15)
    except ImportError as exc:
        raise ScriptSdkWorkspaceError('client.http.client_api is required to read workspace') from exc
    except ClientApiError as exc:
        message = str(exc) or 'Failed to read workspace'
        if message in {'Authentication required', 'Forbidden'}:
            raise ScriptSdkWorkspaceError(_missing_grant_message()) from None
        raise ScriptSdkWorkspaceError(message) from None
    except Exception as exc:
        raise ScriptSdkWorkspaceError(str(exc) or 'Failed to read workspace') from exc

    if not isinstance(data, dict):
        raise ScriptSdkWorkspaceError('Invalid workspace response')
    return data


def list() -> builtins.list[dict]:
    """返回当前 client 所属 machine 的 pinned paths。"""
    items = _request_workspace().get('items') or []
    return items if isinstance(items, builtins.list) else []


def as_dict() -> dict[str, str]:
    """以 {display_name: path} 形式返回 pinned paths。"""
    result = {}
    for item in list():
        if not isinstance(item, dict):
            continue
        name = _safe_text(item.get('display_name') or item.get('name'))
        path = _safe_text(item.get('path'))
        if name and path:
            result[name] = path
    return result


def get(display_name: str, default: str = '') -> str:
    """按 display_name 获取 pinned path，找不到时返回 default。"""
    target = _safe_text(display_name)
    if not target:
        raise ValueError('display_name is required')
    for name, path in as_dict().items():
        if name == target:
            return path
    return default


def path(display_name: str, default: str = '') -> str:
    return get(display_name, default=default)
