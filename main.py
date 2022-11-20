import socket
import time
import threading

from queue import Queue

import requests


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


    print('''\033[1;97m██████╗░███████╗░█████╗░██████╗░
██╔══██╗██╔════╝██╔══██╗██╔══██╗
██████╔╝█████╗░░███████║██║░░██║
██╔══██╗██╔══╝░░██╔══██║██║░░██║
██║░░██║███████╗██║░░██║██████╔╝
╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝╚═════╝\033[0m\n''')


print("""Welcome to our DevNet project work! Our program is focused on network analysis and troubleshooting.
Functions of this program:
===============================================================================================================
1) Network scanner
This program scans the victim to locate open ports available on a particular host.
===============================================================================================================
2) Checking the availability of HTTP methods
Given Python crypt with which we can connect to the target web server and enumerate the available HTTP methods.
===============================================================================================================
""")
choice=int(input('Please, enter the number of the feature you want to use: '))
if choice==1:
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
if choice==2:
    target = input('Enter the host to be scanned: ')
    method_list = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'TEST']
    for method in method_list:
        req = requests.request(method, target)
        print(method, req.status_code, req.reason)
    if method == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
        print('Cross Site Tracing(XST) is possible')









