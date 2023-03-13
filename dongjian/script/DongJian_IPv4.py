from DongJian import *
import socket
import fcntl
import struct

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
	"proto": "IPv4"
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


def ipv4_header_checksum(msg):
    n = len(msg)
    m = n % 2
    if m:
        return "\x00\x00"
    sum = 0
    for i in range(0, n - m, 2):
        sum += (msg[i]) + ((msg[i + 1]) << 8)
    # cksum = (sum >> 16) + (sum & 0xffff)
    # cksum = ~cksum
    # return struct.pack(">H", cksum)
    sum = ~sum & 0xffff
    return struct.pack(">H", sum)


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


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        net_interface = kwargs["net_interface"]
        l2_dst = kwargs["l2_dst"]
    except KeyError as e:
        print("lack of parameter net_interface")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=net_interface, proto="raw-l3", ethernet_proto=0x0800, l2_dst=transtomac(l2_dst)),
        ),
        **kwargs
    )

    s_initialize("IPv4")
    if s_block_start("ipv4"):
        if s_block_start("ipv4_header"):
            s_static(b"\x45", "ver")
            s_byte(value=0x00, name="Type of Service", endian=">")
            s_size(name="total length", block_name="ipv4", length=2, inclusive=False, fuzzable=False, endian=">")
            s_static("\x0c\x08", "Identification")
            s_static("\x00", "Flags")
            s_static("\x00", "offset")
            s_byte(value=0x80, name="Time to Live", endian=">")
            s_byte(value=0xff, name="protocol", endian=">")
            s_checksum(name="header checksum", block_name="ipv4_header", length=2, algorithm="ipv4", fuzzable=False,
                       endian=">")
            # s_checksum(name="header checksum", block_name="ipv4_header", length=2, algorithm=ipv4_header_checksum, fuzzable=False, endian=">")
            s_static(get_ip_addr(bytes(kwargs["net_interface"], encoding="utf8")), name="src_ip")
            s_static(socket.inet_aton(target_ip), name="dst_ip")
        s_block_end("ipv4_header")
        if s_block_start(name="data"):
            s_random("\x00", min_length=2, max_length=255, num_mutations=1000)
        s_block_end("data")
    s_block_end("ipv4")

    sess.connect(s_get("IPv4"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "172.16.145.25"
    start_cmds = []
    proc_name = ""
    pport = 0
    dport= 0
    net_interface = "lo"
    l2_dst = "309c23c4f372"
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface=net_interface, l2_dst=l2_dst)