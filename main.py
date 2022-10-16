import socket
import time
import threading

from queue import Queue


class ScannerIp:
    def __init__(self, ip):
        self.ip = t_IP

    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            con = s.connect((t_IP, port))
            with print_lock:
                print(port, 'is open')
            con.close()
        except:
            pass

    def threader(self):
        while True:
            worker = q.get()
            ScannerIp.portscan(worker)
            q.task_done()


socket.setdefaulttimeout(0.25)
print_lock = threading.Lock()

target = input('Enter the host to be scanned: ')
t_IP = socket.gethostbyname(target)
print('Starting scan on host: ', t_IP)

ip = ScannerIp(t_IP)

q = Queue()
startTime = time.time()

for x in range(100):
    t = threading.Thread(target=ip.threader)
    t.daemon = True
    t.start()

for worker in range(1, 500):
    q.put(worker)

q.join()
print('Time taken:', time.time() - startTime)
