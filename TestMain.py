import unittest
import socket
from main import *


class TestMain(unittest.TestCase):
    def test_IfIpIsTrue(self):
        self.assertTrue(socket.inet_aton(t_IP))

if __name__ == "__main__":
    unittest.main()
