import threading


class ConnectionManager:
    def __init__(self):
        self._connections = []
        self._lock = threading.RLock()

    def add(self, conn):
        with self._lock:
            self._connections.append(conn)

    def remove(self, conn):
        with self._lock:
            if conn in self._connections:
                self._connections.remove(conn)

    def all(self):
        """
        返回当前连接列表快照
        """
        with self._lock:
            return list(self._connections)

    def list(self):
        """
        兼容旧接口，返回当前连接列表快照
        """
        return self.all()

    def get(self, index):
        with self._lock:
            return self._connections[index]

    def get_by_client_id(self, client_id):
        with self._lock:
            for conn in self._connections:
                if conn.info.get('id') == client_id:
                    return conn
        raise KeyError(f'Connection not found: {client_id}')

    def last(self):
        with self._lock:
            return self._connections[-1]

    def __getitem__(self, index):
        return self.get(index)

    def __len__(self):
        with self._lock:
            return len(self._connections)

    def __iter__(self):
        return iter(self.all())

    def __contains__(self, item):
        with self._lock:
            return item in self._connections






