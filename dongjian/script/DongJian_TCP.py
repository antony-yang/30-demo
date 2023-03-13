import fcntl
import socket
import struct
import uuid

from DongJian import *
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
		"l2_dst": {
			"ness": 1,
			"default": "2c331151213c"
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
	"proto": "TCP"
}
# !/usr/bin/python

# A partial MDNS fuzzer.  Could be made to be a DNS fuzzer trivially
# Charlie Miller <cmiller@securityevaluators.com>
from DongJian import ip_constants

def get_mac_addr(): #get mac address and trans it into hex byte format
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    print(mac)
    return transtomac(mac)


def transtomac(mac):
    sss = 0
    for s in range(0, 11, 2):
        ss = TransToInt(mac[s]) * 16 + TransToInt(mac[s+1])
        sss = sss*256 + ss
    mac2 = sss.to_bytes(6, byteorder="big", signed=False)
    return mac2


def TransToInt(c): #trans a char to a int
    if '0' <= c <= '9':
        return int(c)
    if 'a' <= c <= 'z':
        return ord(c) - ord('a') + 10
    return 0

def get_ip_addr(ifname): # get interface's ip address, parameter ifname only accept bytes(do not accept str class)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', ifname[:15])
    )[20:24]

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        kwargs["net_interface"]  # iframe
        kwargs["l2_dst"]  # router's mac address
    except KeyError as e:
        print("lack of parameter")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l3", ethernet_proto=0x0800, l2_dst=transtomac(kwargs["l2_dst"]))
        ),
        **kwargs
    )

    s_initialize("TCP_Protocol")
    if s_block_start("TCP"):
        if s_block_start("IP_Header"):
            s_static(value='\x45', name='Version')
            s_static(value='\x00', name='TOS')
            s_size(name='Total Length', block_name='TCP', length=2, inclusive=False, endian='>', fuzzable=False)
            s_static(value='\x2f\xc5', name='ID')
            s_static(value='\x00\x00', name='Flags')
            s_static(value='\x80', name='Time')
            s_static(value='\x06', name='Protocol')
            s_checksum(name='checksum1', block_name='IP_Header', algorithm='ipv4', length=2, endian='>',
                       fuzzable=False)
            if s_block_start('src'):
                s_static(get_ip_addr(bytes(kwargs["net_interface"], encoding="utf-8")), "Src_ip")
            s_block_end('src')
            if s_block_start('dst'):
                s_static(socket.inet_aton(target_ip), "Dst_ip")
            s_block_end('dst')
        s_block_end("IP_Header")
        if s_block_start('TCP_Header'):
            s_word(value=0, endian='>', fuzzable=True, name='SrcPort')
            s_word(value=0, endian='>', fuzzable=True, name='DstPort')
            s_static(value='\x52\xc5\xb7\xc4', name='Seq_num')
            s_static(value='\x00\x00\x00\x00', name='Ack_num')
            s_static(value='\50', name='Header_length')
            # s_static(value='\x10',name='Flags')
            s_group(name='tcp_flags',
                    values=['\x01', '\x02', '\x03', '\x04', '\x05', '\x06'])
            # s_size(name='Head Length', block_name='TCP_Header', length = 1, inclusive=False, endian='>', fuzzable=False, math = lambda x: int(x / 4))
            # s_bit_field(name='Reverse', width=6, value=0b100001, fuzzable=False)
            # s_bit_field(name='TCP_Flags', width=6, value=0b101001, fuzzable=False)
            s_static(value='\xfa\xf0', name='Window_size')
            s_checksum(name='tcp_checksum', block_name='TCP_Header', algorithm='crc32', length=2, endian='>', fuzzable=False)
            s_static(value='\x00\x00', name='Urgent_point')
        s_block_end('TCP_Header')
        if s_block_start('TCP_Data'):
            s_string(value='11111111abdb111111iiiiiiiiibggfgggg', padding=b"\u0000", max_len=1490, fuzzable=True)
        s_block_end('TCP_Data')
    s_block_end("TCP")

    sess.connect(s_get('TCP_Protocol'))
    sess.fuzz()


if __name__=="__main__":
    start_cmds = []
    proc_name = ""
    target_ip = "127.0.0.1"
    pport = 0
    dport = 0
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface="ens33", l2_dst="2c331151213c")

