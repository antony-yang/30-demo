#!/usr/bin/env python
# Designed for use with DongJian v0.0.8

from DongJian import *
from binascii import hexlify
import uuid
import socket
import fcntl
import struct

socket.setdefaulttimeout(8)
param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 4789
		},
		"dst_mac": {
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
	"proto": "VxLan"
}

def get_mac_addr():  # get mac address and trans it into hex byte format
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    # print(mac)
    sss = 0
    for s in range(0, 11, 2):
        ss = TransToInt(mac[s]) * 16 + TransToInt(mac[s + 1])
        sss = sss * 256 + ss
    mac2 = sss.to_bytes(6, byteorder="big", signed=False)
    return mac2


def TransToInt(c):  # trans a char to a int
    if '0' <= c <= '9':
        return int(c)
    if 'a' <= c <= 'z':
        return ord(c) - ord('a') + 10
    return 0


def get_ip_addr(ifname): # get interface's ip address, parameter ifname only accept bytes(do not accept str class)
    ret = b"\x00" * 4
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ret=fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', ifname[:15])
        )[20:24]
    except OSError as ex:
        print("error: " + str(ex))
    return ret




def transtomac(mac):
    sss = 0
    for s in range(0, 11, 2):
        ss = TransToInt(mac[s]) * 16 + TransToInt(mac[s+1])
        sss = sss*256 + ss
    mac2 = sss.to_bytes(6, byteorder="big", signed=False)
    return mac2

def up(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    if ((node.names['Vlan Flags']._value) & 0x8000 > 0):
        node.names["Vlan ID"]._value = 0x0001
    else:
        node.names["Vlan ID"]._value = 0x0000



def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        kwargs["net_interface"]  # iframe
        # kwargs["l2_dst"]  # router's mac address
        # kwargs["dst_ip"]  # pinging target`
        kwargs['dst_mac']
    except KeyError as e:
        print("lack of parameter")
        return 0

    session = Session(
        target=Target(
            connection=SocketConnection(
                target_ip,
                pport,
                proto="udp"
            )
        ),
        **kwargs
    )

    s_initialize('vxlan')
    if s_block_start('Vxlan Header'):
        s_bit_field(value=1, name='Vlan Flags', width=8, fuzzable=True)
        s_static(name='Vlan ID', value='\x00\x00\x00')
        s_bit_field(value=0xFFFFFF, width=24, name='VNI', fuzzable=True)
        s_bit_field(value=0x00, name='reserved', width=8, fuzzable=False)
        s_block_end('Vxlan Header')
    if s_block_start('Outer Ethernet Header'):
        s_static(name='DstMac', value=transtomac(kwargs["dst_mac"]))
        s_static(name='SrcMac', value=get_mac_addr())
        s_static(name='Vlan Type', value='\x81\x00')
        s_static(name='Vlan Tag', value='\x00\x00')
        s_static(name='Ether Type', value='\x08\x00')
    s_block_end('Outer Ethernet Header')
    if s_block_start("Outer IP Header"):
        s_static(value='\x45', name='Version')
        s_static(value='\x00', name='TOS')
        s_size(name='Total Length', block_name='Outer IP Header', length=2, inclusive=False, endian='>', fuzzable=False)
        # s_static(name='len', value='\x2c')
        s_static(value='\x2f\xc5', name='ID')
        s_static(value='\x00\x00', name='Flags')
        s_static(value='\x80', name='Time')
        s_static(value='\x11', name='Protocol')
        s_checksum(name='checksum1', block_name='Outer IP Header', algorithm='ipv4', length=2, endian='>',
                   fuzzable=False)
        if s_block_start('src'):
            s_static(get_ip_addr(bytes(kwargs["net_interface"], encoding="utf8")), name="src_ip")
        s_block_end('src')
        if s_block_start('dst'):
            s_static(socket.inet_aton(target_ip), "dst_ip")
        s_block_end('dst')
    s_block_end("Outer IP Header")
    if s_block_start('Outer UDP Header'):
        s_word(value=12345, endian='>', fuzzable=True, name='SrcPort')
        s_word(value=4789, endian='>', fuzzable=False, name='DstPort')
        s_size(name='udp length', block_name='Outer UDP Header', length=2, inclusive=False, fuzzable=False, endian='>')
        s_checksum(block_name='Outer UDP Header', algorithm='udp', length=2, endian='>',
                   ipv4_src_block_name='src', ipv4_dst_block_name='dst', fuzzable=False)
    s_block_end(name='Outer UDP Header')

    if s_block_start('Payload'):
        s_random(name="body", value="\x00", min_length=1, max_length=1492, num_mutations=10000)
    s_block_end('Payload')

    session.connect(s_get("vxlan"))

    session.fuzz()

if __name__ == "__main__":
    start_cmds = []
    proc_name = ""
    target_ip = "10.38.4.17"
    pport = 4789
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface='ens33', dst_mac="0180c2000000")
