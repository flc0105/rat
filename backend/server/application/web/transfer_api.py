import hmac
import secrets
import threading

from server.config.config import WEB_FILE_TRANSFER_PORT


class WebTransferApi:
    def __init__(self, transfer_service):
        self.transfer_service = transfer_service
        self._browser_upload_grant_lock = threading.RLock()
        self._browser_upload_grants = {}

    def list_transfers(self, tab_id: str = ''):
        return self.transfer_service.list_transfers(tab_id=tab_id)

    def create_browser_upload_transfer(
        self,
        *,
        client_id: str,
        filename: str,
        total_bytes,
        destination_path: str = '',
        tab_id: str = '',
    ):
        normalized_client_id = str(client_id or '').strip()
        normalized_filename = str(filename or '').strip()
        normalized_tab_id = str(tab_id or '').strip()
        if not normalized_client_id:
            raise ValueError('client_id is required')
        if not normalized_filename:
            raise ValueError('filename is required')
        if not normalized_tab_id:
            raise ValueError('tab_id is required')

        transfer = self.transfer_service.create_transfer(
            client_id=normalized_client_id,
            direction='server_to_client',
            filename=normalized_filename,
            destination_path=str(destination_path or '').strip(),
            tab_id=normalized_tab_id,
            stage='uploading_to_server',
            total_bytes=total_bytes,
            metadata={
                'source': 'remote_file_upload',
                'browser_stage': True,
            },
        )
        transfer_id = str(transfer.get('transfer_id') or '').strip()
        upload_token = secrets.token_urlsafe(32)
        with self._browser_upload_grant_lock:
            self._browser_upload_grants[transfer_id] = {
                'token': upload_token,
                'client_id': normalized_client_id,
                'filename': normalized_filename,
                'total_bytes': total_bytes,
                'destination_path': str(destination_path or '').strip(),
                'tab_id': normalized_tab_id,
            }

        return {
            **transfer,
            'browser_upload_port': WEB_FILE_TRANSFER_PORT,
            'browser_upload_path': f'/api/transfers/browser-upload/{transfer_id}/content',
            'browser_upload_token': upload_token,
        }

    def consume_browser_upload_grant(self, transfer_id: str, token: str) -> dict | None:
        normalized_id = str(transfer_id or '').strip()
        normalized_token = str(token or '').strip()
        if not normalized_id or not normalized_token:
            return None

        with self._browser_upload_grant_lock:
            grant = self._browser_upload_grants.get(normalized_id)
            if not grant:
                return None

            expected_token = str(grant.get('token') or '')
            if not expected_token or not hmac.compare_digest(normalized_token, expected_token):
                return None

            self._browser_upload_grants.pop(normalized_id, None)
            return {
                key: value
                for key, value in grant.items()
                if key != 'token'
            }

    def revoke_browser_upload_grant(self, transfer_id: str):
        normalized_id = str(transfer_id or '').strip()
        if not normalized_id:
            return
        with self._browser_upload_grant_lock:
            self._browser_upload_grants.pop(normalized_id, None)

    def update_browser_upload_progress(
        self,
        transfer_id: str,
        *,
        transferred_bytes,
        total_bytes=None,
        tab_id: str = '',
    ):
        updated = self.transfer_service.update_progress(
            transfer_id,
            transferred_bytes,
            tab_id=str(tab_id or '').strip(),
            stage='uploading_to_server',
            total_bytes=total_bytes,
            expected_stage='uploading_to_server',
        )
        if updated is None:
            raise ValueError('transfer not found')
        return updated

    def mark_browser_upload_staged(
        self,
        transfer_id: str,
        *,
        total_bytes=None,
        tab_id: str = '',
    ):
        patch = {
            'stage': 'preparing',
            'metadata': {
                'browser_stage': False,
            },
        }
        if total_bytes is not None:
            patch['total_bytes'] = total_bytes
            patch['transferred_bytes'] = total_bytes

        updated = self.transfer_service.update_transfer(
            transfer_id,
            tab_id=str(tab_id or '').strip(),
            **patch,
        )
        if updated is None:
            raise ValueError('transfer not found')
        return updated


    def fail_upload_transfer(self, transfer_id: str, error: str, *, tab_id: str = ''):
        updated = self.transfer_service.update_transfer(
            transfer_id,
            tab_id=str(tab_id or '').strip(),
            state='failed',
            stage='failed',
            error=str(error or 'Upload failed').strip(),
            metadata={
                'browser_stage': False,
            },
        )
        if updated is None:
            raise ValueError('transfer not found')
        return updated

    def fail_browser_upload_transfer(self, transfer_id: str, error: str, *, tab_id: str = ''):
        self.revoke_browser_upload_grant(transfer_id)
        updated = self.transfer_service.update_transfer(
            transfer_id,
            tab_id=str(tab_id or '').strip(),
            expected_stage='uploading_to_server',
            state='failed',
            stage='failed',
            error=str(error or 'Browser upload failed').strip(),
            metadata={
                'browser_stage': False,
            },
        )
        if updated is None:
            raise ValueError('transfer not found')
        return updated
