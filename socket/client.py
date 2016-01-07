#!/usr/bin/env python
# encoding: utf-8

import socket
import time

if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 8001))
    time.sleep(2)
    sock.send('1')
    print sock.recv(1024)
    sock.close()

