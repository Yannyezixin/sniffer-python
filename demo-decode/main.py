#!/usr/bin/env python
# encoding: utf-8

import socket
import struct
import logging
import ctypes
from ICMPHeader import ICMP

logging.basicConfig(level=logging.DEBUG,format='%(asctime)s %(filename)s:%(lineno)d [%(levelname)s] %(message)s',datefmt='%Y/%m/%d %H:%M:%S')
# host to listen on
HOST = '192.168.199.183'

def main():
    socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while True:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = raw_buffer[0:20]
        # see http://blog.guozengxin.cn/2013/07/25/python-struct-pack-unpack
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        # print iph
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        logging.debug(('IP -> Version: {version}, Header Length: {header},'
                       'TTL: {ttl}, Protocol: {protocol}, Source IP: {source},'
                       'Destination IP: {destination}').format(
                          version = version, header = iph_length,
                          ttl = ttl, protocol = protocol, source = s_addr,
                          destination = d_addr
                      ))

        buf = raw_buffer[iph_length : iph_length + ctypes.sizeof(ICMP)]
        icmp_header = ICMP(buf)

        logging.debug(('ICMP -> Type:%d, Code: %d' % (icmp_header.type, icmp_header.code)))


if __name__ == '__main__':
    main()


