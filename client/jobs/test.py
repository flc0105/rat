import time

from client.jobs.job import Job


class Test(Job):
    def __init__(self):
        super().__init__()

    def run(self):
        time.sleep(2)
        self.is_running = True
        i = 0
        while self.is_running:
            i += 1
            self.send_to_server(1, 'Hello ' + str(i), 0)
            time.sleep(5)
