#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8
import fcntl

from DongJian import *
from DongJian import helpers,ip_constants
import six
import struct
import socket
param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 0,
			"default": 0
		},
		"proc_name": {
			"ness": 0,
			"default": ""
		},
		"target_ip": {
			"ness": 1,
			"default": "127.0.0.1"
		},
		"start_cmds": {
			"ness": 0,
			"default": []
		},
		"net_interface": {
			"ness": 1,
			"default": "ens33"
		}
	},
	"proto": "IGMPv1"
}
IP_HEADER_LEN = 20


def ip_packet(payload, src_ip=b"\x0A\x01\x04\x62",dst_ip=b"\x0A\x01\x04\x14", protocol=b"\x02"):
    """
    Create an IPv4 packet.
    :type payload: bytes
    :param payload: Contents of next layer up.
    :type src_ip: bytes
    :param src_ip: 4-byte source IP address.
    :type dst_ip: bytes
    :param dst_ip: 4-byte destination IP address.
    :type protocol: bytes
    :param protocol: Single-byte string identifying next layer's protocol. Default "\x11" UDP.
    :return: IPv4 packet.
    :rtype: bytes
    """
    ip_header = b"\x45"  # Version | Header Length
    ip_header += b"\x00"  # "Differentiated Services Field"
    ip_header += struct.pack(">H", IP_HEADER_LEN + len(payload))  # Length
    ip_header += b"\x00\x01"  # ID Field
    ip_header += b"\x40\x00"  # Flags, Fragment Offset
    ip_header += b"\x40"  # Time to live
    ip_header += protocol
    ip_header += b"\x00\x00"  # Header checksum (fill in zeros in order to compute checksum)
    ip_header += src_ip
    ip_header += dst_ip

    checksum = struct.pack(">H", helpers.ipv4_checksum(ip_header))
    ip_header = ip_header[:10] + checksum + ip_header[12:]

    return ip_header + payload


def get_ip_addr(ifname): # get interface's ip address, parameter ifname only accept bytes(do not accept str class)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', ifname[:15])
    )[20:24]


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        #w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        w = msg[i] + (msg[i + 1] << 8)
        s = carry_around_add(s, w)
    return (~s & 0xffff).to_bytes(2, byteorder="little", signed=False)


def fuzz(start_cmds, proc_name, target_ip, pport, dport,  *args, **kwargs):

    session = Session(
        target=Target(
            connection = SocketConnection(host=kwargs['net_interface'], proto='raw-l3')
        ),
        **kwargs
    )

    s_initialize("IGMPv1")
    s_block_start("ipv4")
    if s_block_start("ipv4_header"):
        s_static(b"\x45", "ver")
        s_static(b"\x00", "TOS")
        ###########################################
        s_size(name="total length", block_name="ipv4", length=2, inclusive=False, fuzzable=False, endian=">")
        s_static("\x0c\x08", "Identification")
        s_static("\x40", "Flags")
        s_static("\x00", "offset")
        s_byte(value=0x80, name="ttl", endian=">")
        s_static("\x02", "protocol")
        s_checksum(name="header checksum", block_name="ipv4_header", length=2, algorithm="ipv4", fuzzable=False,
                   endian=">")
        if s_block("ipv4_src"):
            s_static(get_ip_addr(bytes(kwargs["net_interface"], encoding="utf-8")), "src_ip")  #
        s_block_end()
        if s_block("ipv4_dst"):
            s_static(socket.inet_aton(target_ip), "dst_ip")
        s_block_end()
    s_block_end("ipv4_header")
    s_block_start("igmp") #, None, ip_packet
    s_static("\x11")    #version query
    s_static("\x00")    #unused
    #s_static("\x00\x00")    #checksum
    s_checksum(block_name="igmp", algorithm=checksum, endian=">", fuzzable=False, length=2)
    s_byte(0, signed=True, full_range=True) #groupaddr
    s_byte(0, signed=True, full_range=True) #groupaddr
    s_byte(0, signed=True, full_range=True) #groupaddr
    s_byte(0, signed=True, full_range=True) #groupaddr
    s_block_end("igmp")
    s_block_end("ipv4")

    session.connect(s_get("IGMPv1"))
    session.fuzz()


if __name__ == "__main__":
    target_ip = "10.38.4.16"
    start_cmds = []
    proc_name = ""
    pport = 0
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True,
        net_interface="ens33")
