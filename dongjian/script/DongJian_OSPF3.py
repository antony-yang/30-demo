from DongJian import *
import socket
import struct
import fcntl
from netifaces import ifaddresses, AF_INET6
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
	"proto": "OSPF3"
}

def get_ipv6_addr(iframe):
    ipv6_addr = ifaddresses(iframe)[AF_INET6][0]['addr'].split("%")[0]
    return socket.inet_pton(AF_INET6, ipv6_addr)


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
    return fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24]


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    try:
        kwargs["net_interface"]  # iframe
        kwargs["l2_dst"]  # router's mac address
    except KeyError as e:
        print("lack of parameter")
        return 0
    sess = Session(
        target=Target(
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l3", ethernet_proto=0x86dd, l2_dst=transtomac(kwargs["l2_dst"]))
        ),
        **kwargs
    )

    s_initialize("OSPFv3_hello")  #hello
    if s_block_start("ipv6_header"):
        s_static("\x60\x00\x00\x00", name="version and DSCP")
        s_size(name="upper_length", block_name="ospf", length=2, endian=">", fuzzable=False)
        s_static(value="\x59", name="next header")
        s_random(value="\x40", name="hop limit", min_length=1, max_length=1, num_mutations=255)
        s_static(value=get_ipv6_addr(kwargs['net_interface']), name="ipv6.src")
        s_string(value="\x00", name="ipv6.dst", size=16)
    s_block_end("ipv6_header")

    if s_block_start("ospf"):
        if s_block_start("ospf header"):
            s_static("\x03", "ospf_version")
            s_static("\x01", "ospf_type")
            s_size(name="packet length", block_name="ospf", length=2, inclusive=False, fuzzable=False, endian=">")
            s_string(value="\x00\x00\x00\x00", name="router id", size=4)
            s_string(value="\x00\x00\x00\x00", name="area id", size=4)
            s_checksum(name="ospf checksum", block_name="ospf", length=2, algorithm="ipv6", fuzzable=False,
                       endian=">", ipv6_block_name="ipv6_header")
            #s_checksum(name="ospf checksum", block_name="ospf", length=2, algorithm="ipv4", fuzzable=False, endian=">")
            s_static("\x00\x00", "reserved")
            s_static("\x00\x00\x00\x00\x00\x00\x00\x00", "Authentication")
        s_block_end("ospf header")
        if s_block_start("hello packet"):
            s_static(socket.inet_aton("255.255.255.0"), "network mask")
            s_string(value="\x00\x10", name="hello interval", size=2)
            s_string(value="\x00", name="options", size=1)
            s_static("\x01", "pri")
            s_random(value="\x00\x00\x00\x40", name="route dead interval", min_length=4, max_length=4, num_mutations=100000)
            #s_string(value="\x00\x00\x00\x40", name="route dead interval", size=4)
            s_static(socket.inet_aton("0.0.0.0"), "designated router")
            s_static(socket.inet_aton("0.0.0.0"), "backup designated router")
            s_static(socket.inet_aton("0.0.0.0"), "active neighbor")
        s_block_end("hello packet")
    s_block_end("ospf")

    sess.connect(s_get("OSPFv3_hello"))
    sess.fuzz()


if __name__=="__main__":
    start_cmds = []
    proc_name=""
    target_ip = ""
    pport = 0
    dport = 26002
    net_interface = "ens33"
    l2_dst = "000c295be981" #dst_mac
    fuzz(start_cmds, proc_name, target_ip, pport, dport,
         script_start=True, net_interface=net_interface, l2_dst=l2_dst)
