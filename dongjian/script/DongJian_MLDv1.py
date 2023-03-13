from DongJian import *
import socket
from netifaces import ifaddresses, AF_INET6
##############################
#          RFC 2710          #
##############################

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
	"proto": "MLDv1"
}

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

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        net_interface = kwargs["net_interface"]
        l2_dst = kwargs["l2_dst"]
    except KeyError as e:
        print("lack of parameter net_interface")
        return 0
    target_ip = "ff02::1"

    sess = Session(
        target=Target(
            connection=SocketConnection(host=net_interface, proto="raw-l3", ethernet_proto=0x86dd, l2_dst=transtomac(l2_dst)),
        ),
        **kwargs
    )

    ipv6_addr = ifaddresses(net_interface)[AF_INET6][0]['addr'].split("%")[0]
    # Multicast Listener Query
    s_initialize("MLQ")
    if s_block_start("ipv6"):
        if s_block_start(name="IPv6 header"):
            s_static("\x60\x00\x00\x00", name="version and DSCP")
            s_size(block_name="data", length=2, endian=">", fuzzable=False)
            s_static("\x3a", name="next header")  # icmpv6
            s_static("\x01", name="hop limit")
            s_string(socket.inet_pton(AF_INET6, ipv6_addr), size=16, encoding="utf8", name="ipv6.src", fuzzable=False)
            s_string(socket.inet_pton(AF_INET6, target_ip), size=16, encoding="utf8", name="ipv6.dst", fuzzable=False)
        s_block_end("IPv6 header")

        if s_block_start(name="data"):
            s_static("\x82", name="type")
            s_static("\x00", name="code")
            s_checksum(block_name="data", algorithm="ipv6", length=2, endian=">", fuzzable=False, ipv6_block_name="IPv6 header")
            s_string("\x00\x00", name="max response code", size=2, encoding="utf8")
            s_static("\x00\x00", name="reserve")
            s_static("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", name="multicast address")
        s_block_end("data")
    s_block_end("ipv6")

    # Multicast Listener Report and Done
    s_initialize("MLDv1")
    if s_block_start("ipv6"):
        if s_block_start(name="IPv6 header"):
            s_static("\x60\x00\x00\x00", name="version and DSCP")
            s_size(block_name="data", length=2, endian=">", fuzzable=False)
            s_static("\x3a", name="next header")  # icmpv6
            s_static("\x01", name="hop limit")
            s_string(socket.inet_pton(AF_INET6, ipv6_addr), size=16, encoding="utf8", name="ipv6.src", fuzzable=False)
            s_string(socket.inet_pton(AF_INET6, target_ip), size=16, encoding="utf8", name="ipv6.dst", fuzzable=False)
        s_block_end("IPv6 header")

        if s_block_start(name="data"):
            s_group(name="type", values=["\x83", "\x84"])
            s_static("\x00", name="code")
            s_checksum(block_name="data", algorithm="ipv6", length=2, endian=">", fuzzable=False, ipv6_block_name="IPv6 header")
            s_string("\x00\x00", name="max response code", size=2, encoding="utf8")
            s_static("\x00\x00", name="reserve")
            s_random(value="\x00"*16, min_length=16, max_length=16, num_mutations=1000)
        s_block_end("data")
    s_block_end("ipv6")

    sess.connect(s_get("MLQ"))
    sess.connect(s_get("MLDv1"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = ""
    start_cmds = []
    proc_name = ""
    pport = 0
    dport= 0
    net_interface = "lo"
    l2_dst = "333300000016"
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface = net_interface, l2_dst = l2_dst)
