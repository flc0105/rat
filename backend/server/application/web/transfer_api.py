class WebTransferApi:
    def __init__(self, transfer_service):
        self.transfer_service = transfer_service

    def list_transfers(self, tab_id: str = ''):
        return self.transfer_service.list_transfers(tab_id=tab_id)
