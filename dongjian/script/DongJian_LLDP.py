from DongJian import *
import uuid
import socket
import fcntl
import struct
import random
socket.setdefaulttimeout(8)
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
			"ness": 0,
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
	"proto": "LLDP"
}
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


def Trantobit(n):
    a = 0b0000001000000000 + 512
    print(a)
    print(a.to_bytes(2, byteorder="big", signed=False))


def call_backs(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    values = [0b0000100000000000, 0b0000101000000000, 0b0000110000000000, 0b0000111000000000,
              0b0001000000000000, 0b1111111000000000]
    length = len(node.names["body_classid"]._value) + 1
    node.names["tlv_header_classid"]._value = 0b0000001000000000 + length

    length = len(node.names["body_portid"]._value) + 1
    node.names["tlv_header_portid"]._value = 0b0000010000000000 + length

    length = 2 #len(node.names["body_ttl"]._value)
    node.names["tlv_header_ttl"]._value = 0b0000011000000000 + length

    length = len(node.names["body_end"]._value)
    node.names["tlv_header_end"]._value = 0b0000000000000000 + length

    length = len(node.names["tlv_body"]._value)
    node.names["tlv_header"]._value = values[random.randint(0, 5)] + length


def fuzz(start_cmds, proc_name, target_ip, pport, dport,  *args, **kwargs):
    try:
        kwargs["net_interface"]
    except KeyError as e:
        print("lack of parameter net_interface")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l2"),
        ),
        **kwargs
    )
    s_initialize("ethernetII")
    s_block_start(name="EtheII", group="dst")
    s_group(values=["\x01\x80\xc2\x00\x00\x0e", "\x01\x80\xc2\x00\x00\x03", "\x01\x80\xc2\x00\x00\x00"], name="dst")
    s_static(value=get_mac_addr(), name="src")
    s_static(value="\x88\xcc", name="lldp type")
    s_block_start(name="frame body")

    s_bit_field(name="tlv_header_classid", value=0, width=16, endian=">")
    s_block("tlv_body_classid", group="classid")
    s_group(name="classid", values=[b"\x01", b"\x02", b"\x03", b"\x04", b"\x05", b"\x06", b"\x07"])
    s_random(name="body_classid", value="\x00\x00", min_length=1, max_length=255, num_mutations=100)
    s_block_end("tlv_body_classid")

    s_bit_field(name="tlv_header_portid", value=0, width=16, endian=">")
    s_block("tlv_body_portid", group="portid")
    s_group(name="portid", values=[b"\x01", b"\x02", b"\x03", b"\x04", b"\x05", b"\x06", b"\x07"])
    s_random(name="body_portid", value="\x00\x00", min_length=1, max_length=255, num_mutations=100)
    s_block_end("tlv_body_portid")

    s_bit_field(name="tlv_header_ttl", value=0, width=16, endian=">")
    s_block("tlv_body_ttl")
    #s_random(name="body_ttl", value="\x00\x00", min_length=2, max_length=2, num_mutations=100)
    s_bit_field(name="body_ttl", value=2, endian=">", width=16, fuzzable=True)
    s_block_end("tlv_body_ttl")

    s_block(name="tlv")
    s_bit_field(name="tlv_header", value=0, width=16, endian=">")
    s_random(name="tlv_body", value="\x00\x00", min_length=4, max_length=511, num_mutations=100)
    s_block_end("tlv")

    s_bit_field(name="tlv_header_end", value=0, width=16, endian=">")
    s_block("tlv_body_end")
    s_random(name="body_end", value="\x00\x00", min_length=2, max_length=511, num_mutations=100)
    s_block_end("tlv_body_end")

    s_block_end(name="frame body")
    s_block_end(name="EtheII")

    sess.connect(s_get("ethernetII"), callback=call_backs)
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "10.38.4.16"
    start_cmds = []
    proc_name = ""
    pport = 0
    dport=26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface="ens38")