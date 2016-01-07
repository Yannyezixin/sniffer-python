#!/usr/bin/env python
# encoding: utf-8

import socket
import logging

if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 8001))
    sock.listen(5)
    while True:
        connection, address = sock.accept()
        try:
            connection.settimeout(5)
            buf = connection.recv(1024)
            if buf == '1':
                connection.send('welcome to server!')
            else:
                connection.send('please go out!')
        except socket.timeout:
            logging.error('Time out!')
        connection.close()
