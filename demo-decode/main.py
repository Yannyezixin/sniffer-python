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
    socket_protocol = socket.IPPROTO_IP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 80))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while True:
        raw_buffer = sniffer.recvfrom(65565)[0]
        iph_length = parse_ip(raw_buffer)
        parse_icmp(raw_buffer, iph_length)
        parse_tcp(raw_buffer, iph_length)


def parse_tcp(raw_buffer, iph_length):
    tcp_header = raw_buffer[iph_length : iph_length + 20]

    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence =tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4

    logging.debug(('TCP => Source Port: {source_port}, Dest Port: {dest_port}'
                   ' Sequence Number: {sequence} Acknowledgement: {acknowledgement}'
                   ' TCP header length: {tcph_length}').format(
                       source_port = source_port, dest_port = dest_port,
                       sequence = sequence, acknowledgement = acknowledgement,
                       tcph_length = tcph_length
                   ))




def parse_ip(raw_buffer):
    # IP 头
    ip_header = raw_buffer[0:20]

    # 解析IP头
    # see http://blog.guozengxin.cn/2013/07/25/python-struct-pack-unpack
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

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

    return iph_length

def parse_icmp(raw_buffer, iph_length):
    buf = raw_buffer[iph_length : iph_length + ctypes.sizeof(ICMP)]
    icmp_header = ICMP(buf)

    logging.debug(('ICMP -> Type:%d, Code: %d' % (icmp_header.type, icmp_header.code)))



if __name__ == '__main__':
    main()


