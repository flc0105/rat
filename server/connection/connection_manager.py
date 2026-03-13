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

    def list(self):
        with self._lock:
            return list(self._connections)

    def get(self, index):
        with self._lock:
            return self._connections[index]

    def last(self):
        with self._lock:
            return self._connections[-1]