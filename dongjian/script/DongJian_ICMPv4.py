from DongJian import *
import socket
import struct
import fcntl
import random

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
	"proto": "ICMPv4"
}

code = ["\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0a", "\x0b", "\x0c", "\x0d", "\x0e", "\x0f"]


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


def update(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    # print(node.names['code']._value)
    # node.names['code']._value = "\x01"
    # print(node.names['icmp type']._value)
    # print(node.names['icmp type']._mutant_index)
    # print(node.names["icmp type"].num_mutations())
    icmp_type = node.names['icmp type']._value
    if icmp_type == "\x00":
        node.names['code']._value = "\x00"
    elif icmp_type == "\x03":
        node.names['code']._value = code[random.randint(0, 15)]
    elif icmp_type == "\x04":
        node.names['code']._value = code[0]
    elif icmp_type == "\x05":
        node.names['code']._value = code[random.randint(0, 3)]
    elif icmp_type == "\x08":
        node.names['code']._value = code[0]
    elif icmp_type == "\x09":
        node.names['code']._value = code[0]
    elif icmp_type == "\x0a":
        node.names['code']._value = code[0]
    elif icmp_type == "\x0b":
        node.names['code']._value = code[random.randint(0, 1)]
    elif icmp_type == "\x0c":
        node.names['code']._value = code[random.randint(0, 1)]
    elif icmp_type == "\x0d":
        node.names['code']._value = code[0]
    elif icmp_type == "\x0e":
        node.names['code']._value = code[0]
    elif icmp_type == "\x0f":
        node.names['code']._value = code[0]
    elif icmp_type == "\x10":
        node.names['code']._value = code[0]
    elif icmp_type == "\x11":
        node.names['code']._value = code[0]
    elif icmp_type == "\x12":
        node.names['code']._value = code[0]


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        kwargs["net_interface"]  # iframe
        kwargs["l2_dst"]  # router's mac address
    except KeyError as e:
        print("lack of parameter")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l3", ethernet_proto=0x0800, l2_dst=bytes(transtomac(kwargs["l2_dst"])))
        ),
        **kwargs
    )
    s_initialize("ICMPv4")
    if s_block_start("ipv4"):
        if s_block_start("ipv4_header"):
            s_static(b"\x45", "ver")
            s_static(b"\x00", "TOS")
            s_size(name="total length", block_name="ipv4", length=2, inclusive=False, fuzzable=False, endian=">")
            s_static("\x0c\x08", "Identification")
            s_static("\x00", "Flags")
            s_static("\x00", "offset")
            s_byte(value=0x80, name="ttl", endian=">")
            s_static("\x01", "protocol")
            s_checksum(name = "header checksum", block_name="ipv4_header", length=2, algorithm="ipv4", fuzzable=False, endian=">")
            s_static(get_ip_addr(bytes(kwargs["net_interface"], encoding="utf-8")), "src_ip")
            s_static(socket.inet_aton(target_ip), "dst_ip")
        s_block_end("ipv4_header")
        if s_block_start(name="icmp", group="icmp type"):
            s_group(name="icmp type",
                    values=["\x00", "\x03", "\x04", "\x05", "\x08", "\x09", "\x0a", "\x0b", "\x0c", "\x0d", "\x0e",
                            "\x0f", "\x10", "\x11", "\x12"], default_value="\x08")
            s_string(name="code", value="\x00", size=1)
            s_checksum(name="icmp checksum", block_name="icmp", length=2, algorithm="ipv4", fuzzable=False, endian=">")
            s_static("\x00\x01", "Identifier")
            s_static("\x00\x3a", "SequenceNumber")
            s_random(value="\x00", max_length=32,  min_length=0, num_mutations=100)
        s_block_end("icmp")
    s_block_end("ipv4")

    sess.connect(s_get("ICMPv4"), callback=update)
    sess.fuzz()


if __name__=="__main__":
    start_cmds = []
    proc_name = ""
    target_ip = "10.38.4.16"
    pport = 0
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface="ens33", l2_dst="2c331151213c")