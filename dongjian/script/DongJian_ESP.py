import uuid

from DongJian import *
import socket
import struct
import fcntl

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
			"default": "000c29da1b9c"
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
	"proto": "ESP"
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


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        kwargs["net_interface"]
        kwargs["l2_dst"]
    except KeyError as e:
        print("lack of parameter")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l3", ethernet_proto=0x0800,
                                        l2_dst=transtomac(kwargs["l2_dst"]))
        ),
        **kwargs
    )
    s_initialize("ESP")
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
            s_static("\x32", "protocol")
            s_checksum(name="header checksum", block_name="ipv4_header", length=2, algorithm="ipv4", fuzzable=False,
                       endian=">")
            s_static(get_ip_addr(bytes(kwargs['net_interface'], encoding="utf-8")), "source_ip")
            s_static(socket.inet_aton(target_ip), "target_ip")
        s_block_end("ipv4_header")
        if s_block(name="ESP"):
            #s_static("\x5c\x32\x30\x47\x28\xfa\xb7\xd5", name="Initiator SPI")
            s_random(value="\xd1\x09\x4f\xe6", min_length=4, max_length=4, name="ESP SPI", num_mutations=100000)
            s_random(value="\x00\x00\x00\x01", min_length=4, max_length=4, name="ESP Sequence", num_mutations=100000)
            s_random(value="\x00", min_length=0, max_length=144, name="Encrypted Data", num_mutations=10000000)
        s_block_end("ESP")
    s_block_end("ipv4")

    sess.connect(s_get("ESP"))
    sess.fuzz()


if __name__=="__main__":
    start_cmds = []
    proc_name=""
    target_ip = "172.16.145.25"
    pport = 500
    dport = 26002
    net_interface = "ens33"
    l2_dst = "309c23c4f372"
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface=net_interface, l2_dst=l2_dst)