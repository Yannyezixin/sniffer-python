#!/usr/bin/env python
# encoding: utf-8

import socket
import os

# This is your host ip
HOST = '192.168.199.183'

def sniffing(host, win, socket_prot):
    """
        使用 Windows 时要注意一点：我们需要发送一个 IOCTL 包才能将网卡设置为
        混淆模式。另外，虽然 linux 需要使用 ICMP，Windows 却可以以一种独立于
        协议的方式来嗅探收到的数据包。
    """
    while True:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_prot)
        sniffer.bind((host, 0))

        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if win is 1:
            sniffer.ioctl(socket.SIO_RCVALL, socket_RCVALL_ON)

        print sniffer.recvfrom(65565)

def main(host):
    if os.name == 'nt':
        sniffing(host, 1, socket.IPPROTO_IP)
    else:
        sniffing(host, 0, socket.IPPROTO_ICMP)

if __name__ == '__main__':
    main(HOST)
