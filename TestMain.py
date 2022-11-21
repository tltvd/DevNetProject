import unittest
import socket
import urllib.request
from main import *


def try_urlopen(link):
    try:
        urllib.request.urlopen(link)
        return True
    except Exception as ex:
        print(ex)
    return False


def network_connection_check(link):
    if not link.startswith('http'):
        for prefix in ['http://', 'https://']:
            if try_urlopen(prefix + link):
                return True
        return False
    else:
        return urllib.request.urlopen(link)


class TestMain(unittest.TestCase):
    def test_IfIpIsTrue(self):
        self.assertTrue(socket.inet_aton(t_IP))

    def test_connection(self):
        self.assertTrue(network_connection_check(target))

    def test_port_connection(self):
        for port in portsResults:
            self.assertTrue(network_connection_check(target+":"+str(port)))

if __name__ == "__main__":
    unittest.main()
