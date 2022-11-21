import socket
import time
import threading
from termcolor import colored
from queue import Queue
import requests
import os, sys
import struct
import binascii
import webbrowser

import portsDict


class packetAnalyzer:
    socketCreated = False
    socketSniffer = 0

    def analyzeUDPHeader(dataRecv):
        udpHeader = struct.unpack('!4H', dataRecv[:8])
        srcPort = udpHeader[0]
        dstPort = udpHeader[1]
        length = udpHeader[2]
        checksum = udpHeader[3]
        data = dataRecv[8:]

        print('---------- UDP HEADER ----------')
        print('Source Port: %hu' % srcPort)
        print('Destination Port: %hu' % dstPort)
        print('Length: %hu' % length)
        print('Checksum: %hu\n' % checksum)

        return data

    def analyzeTCPHeader(dataRecv):
        tcpHeader = struct.unpack('!2H2I4H', dataRecv[:20])
        srcPort = tcpHeader[0]
        dstPort = tcpHeader[1]
        seqNum = tcpHeader[2]
        ackNum = tcpHeader[3]
        offset = tcpHeader[4] >> 12
        reserved = (tcpHeader[5] >> 6) & 0x03ff
        flags = tcpHeader[4] & 0x003f
        window = tcpHeader[5]
        checksum = tcpHeader[6]
        urgPtr = tcpHeader[7]
        data = dataRecv[20:]

        urg = bool(flags & 0x0020)
        ack = bool(flags & 0x0010)
        psh = bool(flags & 0x0008)
        rst = bool(flags & 0x0004)
        syn = bool(flags & 0x0002)
        fin = bool(flags % 0x0001)

        print('---------- TCP HEADER ----------')
        print('Source Port: %hu' % srcPort)
        print('Destination Port: %hu' % dstPort)
        print('Sequence Number: %u' % seqNum)
        print('Acknowledgement: %u' % ackNum)
        print('Flags: ')
        print('    URG: %d | ACK: %d | PSH: %d | RST: %d | SYN: %d | FIN: %d' % (urg, ack, psh, rst, syn, fin))
        print('Window Size: %hu' % window)
        print('Checksum: %hu' % checksum)
        print('Urgent Pointer: %hu\n' % urgPtr)

        return data

    def analyzeIP(dataRecv):
        ipHeader = struct.unpack('!6H4s4s', dataRecv[:20])
        version = ipHeader[0] >> 12
        ihl = (ipHeader[0] >> 8) & 0x0f
        tos = ipHeader[0] & 0x00ff
        totalLength = ipHeader[1]
        ipID = ipHeader[2]
        flags = ipHeader[3] >> 13
        fragOffset = ipHeader[3] & 0x1fff
        ipTTL = ipHeader[4] >> 8
        ipProtocol = ipHeader[4] & 0x00ff
        checksum = ipHeader[5]
        srcAddr = socket.inet_ntoa(ipHeader[6])
        dstAddr = socket.inet_ntoa(ipHeader[7])
        data = dataRecv[20:]

        print('---------- IP HEADER ----------')
        print('Version: %hu' % version)
        print('IHL: %hu' % ihl)
        print('TOS: %hu' % tos)
        print('Length: %hu' % totalLength)
        print('ID: %hu' % ipID)
        print('Offset: %hu' % fragOffset)
        print('TTL: %hu' % ipTTL)
        print('Protocol: %hu' % ipProtocol)
        print('Checksum: %hu' % checksum)
        print('Source IP: %s' % srcAddr)
        print('Destination IP: %s\n' % dstAddr)

        if ipProtocol == 6:
            tcp_udp = "TCP"
        elif ipProtocol == 17:
            tcp_udp = "UDP"
        else:
            tcp_udp = "Other"

        return data, tcp_udp

    def analyzeEtherHeader(dataRecv):
        ipBool = False
        etherHeader = struct.unpack('!6s6sH', dataRecv[:14])
        dstMac = binascii.hexlify(etherHeader[0]).decode()
        srcMac = binascii.hexlify(etherHeader[1]).decode()
        protocol = etherHeader[2] >> 8
        data = dataRecv[14:]

        print('---------- ETHERNET HEADER -----------')
        print('Destination MAC: %s:%s:%s:%s:%s:%s' % (
            dstMac[0:2], dstMac[2:4], dstMac[4:6], dstMac[6:8], dstMac[8:10], dstMac[10:12]))
        print('Source MAC: %s:%s:%s:%s:%s:%s' % (
            srcMac[0:2], srcMac[2:4], srcMac[4:6], srcMac[6:8], srcMac[8:10], srcMac[10:12]))
        print('Protocol: %hu\n' % protocol)

        if protocol == 0x08:
            ipBool = True

        return data, ipBool

    def startPacketAnalyzer(self):
        socketCreated = False
        socketSniffer = 0

        if socketCreated == False:
            socketSniffer = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            socketCreated = True;

        dataRecv = socketSniffer.recv(2048)
        os.system('clear')

        dataRecv, ipBool = analyzeEtherHeader(dataRecv)

        if ipBool:
            dataRecv, tcp_udp = analyzeIP(dataRecv)
        else:
            return

        if tcp_udp == "TCP":
            dataRecv = analyzeTCPHeader(dataRecv)
        elif tcp_udp == "UDP":
            dataRecv = analyzeUDPHeader(dataRecv)
        else:
            return


class ScannerIp:
    def __init__(self, ip):
        self.ip = t_IP

    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            con = s.connect((t_IP, port))
            with print_lock:
                portsResults.append(port)
                print("---------------------------------------------------")
                print(colored("[+] Port %d is open" % (port), 'green'))
                print("This is "+ portsDict.ports.get(str(port))+" port")
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
3) Packet Analyzer
This Python program will analyze each packet received by the host machine and print out the contents of its Ethernet, 
IP, and TCP/UDP headers to the console. The script will differentiate the packet's protocol as either TCP or UDP 
and print their respective headers to the console.
===============================================================================================================
""")
choice = int(input('[*] Please, enter the number of the feature you want to use: '))
portsResults = []
if choice == 1:
    socket.setdefaulttimeout(0.25)
    print_lock = threading.Lock()
    target = input('[*] Enter the host to be scanned: ')
    portNumber = int(input('[*] Enter the number of ports you want to scan: '))
    t_IP = socket.gethostbyname(target)
    print("[Scanning Target...] "+str(t_IP))

    ip = ScannerIp(t_IP)

    q = Queue()
    startTime = time.time()

    for x in range(100):
        t = threading.Thread(target=ip.threader)
        t.daemon = True
        t.start()

    for worker in range(1, portNumber):
        q.put(worker)

    q.join()
if choice == 2:
    target = input('[*] Enter the host to be scanned: ')
    method_list = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'TEST']
    for method in method_list:
        req = requests.request(method, target)
        print(method, req.status_code, req.reason)
    if method == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
        print('Cross Site Tracing(XST) is possible')
if choice == 3:
    packet = packetAnalyzer()
    packet.startPacketAnalyzer()
if choice==4:

    target = input('[*] Enter the host to be scanned: ')

    webbrowser.open_new_tab('http://192.168.1.160/DVWA/vulnerabilities/xss_r/?name=<script>alert(document.cookie)</script>#')

