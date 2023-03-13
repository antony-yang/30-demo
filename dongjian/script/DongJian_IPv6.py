from DongJian import *
import socket
from netifaces import ifaddresses, AF_INET6
import re
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
	"proto": "IPv6"
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

def ipv6_check(addr):
    ip6_regex = (r'(^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$)|'
                 r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|'
                 r'(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|'
                 r'(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|'
                 r'(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|'
                 r'(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|'
                 r'(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|'
                 r'(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|(\A:(:[0-9a-f]{1,4}){1,7}\Z)|'
                 r'(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|'
                 r'(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|'
                 r'(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
                 r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
                 r'(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
                 r'(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
                 r'(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
                 r'(\A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
                 r'(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)')
    return bool(re.match(ip6_regex, addr, flags=re.IGNORECASE))


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        net_interface = kwargs["net_interface"]
        l2_dst = kwargs["l2_dst"]
    except KeyError as e:
        print("lack of parameter net_interface")
        return 0
    if not ipv6_check(target_ip):
        target_ip = "::1"

    #############################
    try:
        queue = kwargs['queue']
    except Exception as e:
        queue = None
    #############################

    sess = Session(
        target=Target(
            connection=SocketConnection(host=net_interface, proto="raw-l3", ethernet_proto=0x86dd, l2_dst=transtomac(l2_dst)),
        ),
        **kwargs
    )

    ipv6_addr = ifaddresses(net_interface)[AF_INET6][0]['addr'].split("%")[0]
    s_initialize("IPv6")
    if s_block_start(name="IPv6 header"):
        s_static("\x60\x00\x00\x00", name="version and DSCP")

        s_size(block_name="data", length=2, endian=">", fuzzable=False)
        s_random("\xff", name="next header", min_length=1, max_length=1)
        s_static("\x01", name="hop limit")
        s_string(socket.inet_pton(AF_INET6, ipv6_addr), size=16, encoding="utf8", name="ipv6.src", fuzzable=False)
        s_string(socket.inet_pton(AF_INET6, target_ip), size=16, encoding="utf8", name="ipv6.dst", fuzzable=False)
        s_block_end("IPv6 header")


    if s_block_start(name="data"):
        s_random("\x00", min_length=1, max_length=255, num_mutations=1000)
        s_block_end("data")

    sess.connect(s_get("IPv6"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "ff02::cde0:9295:459b:17a7"
    start_cmds = []
    proc_name = ""
    pport = 0
    dport= 0
    net_interface = "lo"
    l2_dst = "2c331151213c"
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface=net_interface, l2_dst=l2_dst)
