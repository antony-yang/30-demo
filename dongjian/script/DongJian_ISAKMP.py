import fcntl
import socket
import struct

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
	"proto": "ISAKMP"
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


def get_ip_addr(ifname): # get interface's ip address, parameter ifname only accept bytes(do not accept str class)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', ifname[:15])
    )[20:24]


def fuzz(start_cmds, proc_name, target_ip, pport, dport,  *args, **kwargs):

    sess = Session(
        target=Target(
            #connection=SocketConnection(host=target_ip, port=pport, proto="udp"),
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l3", ethernet_proto=0x0800,
                                        l2_dst=transtomac(kwargs["l2_dst"]))
        ),
        **kwargs
    )
    s_initialize("ISAKMP")
    if s_block_start("ipv4"):
        if s_block_start("ipv4_header"):
            s_static(b"\x45", "ver")
            s_static(b"\x00", "DSF")
            #s_static("\x00\x38", "length")
            s_size(name="total length", block_name="ipv4", length=2, inclusive=False, fuzzable=False, endian=">")
            s_static("\x0a\xd5", "Identification")
            s_static("\x00", "Flags_ipv4")
            s_static("\x00", "offset")
            s_string(value="\x40", name="ttl", encoding="utf-8", max_len=1)
            #s_static("\x32", "protocol")
            s_static("\x11", "protocol")
            s_checksum(name="header checksum", block_name="ipv4_header", length=2, algorithm="ipv4", fuzzable=False,
                       endian=">")
            s_static(get_ip_addr(bytes(kwargs['net_interface'], "utf-8")), "source_ip")
            s_static(socket.inet_aton(target_ip), "target_ip")
        s_block_end("ipv4_header")
        if s_block_start("udp"):
            s_static("\x01\xf4", name="source_port")
            s_static("\x01\xf4", name="des_port")
            s_size(name="udp length", block_name="udp", length=2, inclusive=False, fuzzable=False, endian=">")
            s_checksum(name="udp checksum", block_name="udp", length=2, algorithm="ipv4", fuzzable=False,
                       endian=">")
            if s_block(name="request"):
                s_random(value="\x5c\x32\x30\x47\x28\xfa\xb7\xd5", min_length=8, max_length=8, name="Initiator SPI", num_mutations=100000)
                s_random(value="\xe0\x6d\xe1\xe1\x37\x67\x6c\x2e", min_length=8, max_length=8, name="Responder SPI", num_mutations=100000)
                #s_static("\x5c\x32\x30\x47\x28\xfa\xb7\xd5", name="Initiator SPI")
                #s_static("\xe0\x6d\xe1\xe1\x37\x67\x6c\x2e", name="Responder SPI")
                s_static("\x08", name="Next payload")
                s_static("\x10", name="Version")
                s_static("\x20", name="Exchange type")
                s_static(value="\x01",  name="Flags")
                s_static(value="\x80\x00\x00\x00", name="Message ID")
                s_size(block_name="request", name="length", length=4, inclusive=False, fuzzable=False, endian=">")
                #s_static(value="\x80\x00\x00\x00", name="Encrypted Data")
                #s_string(value="\x00", max_len=144, name="Encrypted Data")
                s_random(value="\x00", min_length=0, max_length=144, name="Encrypted Data", num_mutations=36720)
            s_block_end("request")
        s_block_end("udp")
    s_block_end("ipv4")

    sess.connect(s_get("ISAKMP"))
    sess.fuzz()


if __name__=="__main__":
    start_cmds = []
    proc_name=""
    target_ip = "127.0.0.1"
    pport = 500
    dport = 26002
    net_interface = "lo"
    l2_dst = "000c29da1b9c"
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface=net_interface, l2_dst=l2_dst)