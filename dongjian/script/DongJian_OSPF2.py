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
	"proto": "OSPF2"
}

def get_ip_addr(ifname): # get interface's ip address, parameter ifname only accept bytes(do not accept str class)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24]

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
    s_initialize("OSPFv2_hello")  #hello
    if s_block_start("ipv4"):
        if s_block_start("ipv4_header"):
            s_static(b"\x45", "ver")
            s_static(b"\x00", "TOS")
            s_static("\x00\x44", "length")
            #s_size(name="total length", block_name="ipv4", length=2, inclusive=False, fuzzable=False, endian=">")
            s_static("\x0c\x08", "Identification")
            s_static("\x00", "Flags")
            s_static("\x00", "offset")
            s_random(value="\x40", name="ttl", min_length=1, max_length=1, num_mutations=255)
            #s_string(value="\x40", name="ttl", encoding="utf-8", size=1)
            s_static("\x59", "protocol")
            s_checksum(name = "header checksum", block_name="ipv4_header", length=2, algorithm="ipv4", fuzzable=False, endian=">")
            s_static(get_ip_addr(bytes(kwargs["net_interface"], encoding="utf-8")), "src_ip")
            s_static(socket.inet_aton(target_ip), "target_ip")
        s_block_end("ipv4_header")
        if s_block_start("ospf"):
            if s_block_start("ospf header"):
                s_static("\x02", "ospf_version")
                s_static("\x01", "ospf_type")
                s_size(name="packet length", block_name="ospf", length=2, inclusive=False, fuzzable=False, endian=">")
                s_static(get_ip_addr(bytes(kwargs["net_interface"], encoding="utf-8")), "router id")
                s_static(socket.inet_aton("0.0.0.0"), "area id")
                s_checksum(name="ospf checksum", block_name="ospf", length=2, algorithm="ipv4", fuzzable=False, endian=">")
                s_static("\x00\x00", "autype")
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
    s_block_end("ipv4")

    s_initialize("OSPFv2_db")  #database description packet
    if s_block_start("ipv4"):
        if s_block_start("ipv4_header"):
            s_static(b"\x45", "ver")
            s_static(b"\x00", "TOS")
            s_static("\x00\x34", "length")
            #s_size(name="total length", block_name="ipv4", length=2, inclusive=False, fuzzable=False, endian=">")
            s_static("\x0c\x08", "Identification")
            s_static("\x00", "Flags")
            s_static("\x00", "offset")
            s_random(value="\x40", name="ttl", min_length=1, max_length=1, num_mutations=255)
            #s_string(value="\x40", name="ttl", encoding="utf-8", max_len=1)
            s_static("\x59", "protocol")
            s_checksum(name="header checksum", block_name="ipv4_header", length=2, algorithm="ipv4", fuzzable=False,
                       endian=">")
            s_static(get_ip_addr(bytes(kwargs["net_interface"], encoding="utf-8")), "src_ip")
            s_static(socket.inet_aton(target_ip), "target_ip")
        s_block_end("ipv4_header")
        if s_block_start("ospf"):
            if s_block_start("ospf_header"):
                s_static("\x02", "ospf_version")
                s_static("\x02", "ospf_type")
                s_size(name="packet length", block_name="ospf", length=2, inclusive=False, fuzzable=False, endian=">")
                s_static(get_ip_addr(bytes(kwargs["net_interface"], encoding="utf-8")), "router id")
                s_static(socket.inet_aton("0.0.0.0"), "area id")
                s_checksum(name="ospf checksum", block_name="ospf", length=2, algorithm="ipv4", fuzzable=False,
                           endian=">")
                s_static("\x00\x00", "autype")
                s_static("\x00\x00\x00\x00\x00\x00\x00\x00", "Authentication")
            s_block_end("ospf_header")
            if s_block_start("db_description_packet"):
                s_random(value="\x01", name="interface MTU", min_length=1, max_length=1, num_mutations=255)
                #s_string(value="\x00\x0a", size=2, name="interface MTU")
                s_random(value="\x01", name="options", min_length=1, max_length=1, num_mutations=255)
                #s_string(value="\x01",  size=1, name="options")
                s_random(value="\x01", name="db description", min_length=1, max_length=1, num_mutations=255)
                #s_string(value="\x01",  size=1, name="db description")
                s_random(value="\x00\x00\x00\x45", name="db sequence", min_length=4, max_length=4, num_mutations=10000)
                #s_string(value="\x00\x00\x00\x45", size=4, name="db sequence")
            s_block_end("db_description_packet")
        s_block_end("ospf")
    s_block_end("ipv4")

    s_initialize("OSPFv2_lsr")  # link state request packet
    if s_block_start("ipv4"):
        if s_block_start("ipv4_header"):
            s_static(b"\x45", "ver")
            s_static(b"\x00", "TOS")
            s_static("\x00\x38", "length")
            #s_size(name="total length", block_name="ipv4", length=2, inclusive=False, fuzzable=False, endian=">")
            s_static("\x0c\x08", "Identification")
            s_static("\x00", "Flags")
            s_static("\x00", "offset")
            s_random(value="\x40", name="ttl", min_length=1, max_length=1, num_mutations=255)
            #s_string(value="\x40", name="ttl", encoding="utf-8", max_len=1)
            s_static("\x59", "protocol")
            s_checksum(name="header checksum", block_name="ipv4_header", length=2, algorithm="ipv4", fuzzable=False,
                       endian=">")
            s_static(get_ip_addr(bytes(kwargs["net_interface"], encoding="utf-8")), "src_ip")
            s_static(socket.inet_aton(target_ip), "target_ip")
        s_block_end("ipv4_header")
        if s_block_start("ospf"):
            if s_block_start("ospf_header"):
                s_static("\x02", "ospf_version")
                s_static("\x03", "ospf_type")
                s_size(name="packet length", block_name="ospf", length=2, inclusive=False, fuzzable=False, endian=">")
                s_static(get_ip_addr(bytes(kwargs["net_interface"], encoding="utf-8")), "router id")
                s_static(socket.inet_aton("0.0.0.0"), "area id")
                s_checksum(name="ospf checksum", block_name="ospf", length=2, algorithm="ipv4", fuzzable=False,
                           endian=">")
                s_static("\x00\x00", "autype")
                s_static("\x00\x00\x00\x00\x00\x00\x00\x00", "Authentication")
            s_block_end("ospf_header")
            if s_block_start("lsr"):
                s_random(value="\x00\x00\x00\x45", name="ls type", min_length=4, max_length=4, num_mutations=100000)
                #s_string(value="\x00\x00\x00\x01", size=4, name="ls type")
                s_random(value="\x00\x00\x00\x45", name="link state id", min_length=4, max_length=4, num_mutations=100000)
                #s_string(value="\x0a\x26\x00\x01", size=4, name="link state id")
                s_random(value="\x00\x00\x00\x45", name="advertesing router", min_length=4, max_length=4, num_mutations=100000)
                #s_string(value="\x0a\x26\x00\x01", size=4, name="advertesing router")
            s_block_end("lsr")
        s_block_end("ospf")
    s_block_end("ipv4")

    sess.connect(s_get("OSPFv2_hello"))
    sess.connect(s_get("OSPFv2_db"))
    sess.connect(s_get("OSPFv2_lsr"))
    sess.fuzz()


if __name__=="__main__":
    start_cmds = []
    proc_name=""
    target_ip = "127.0.0.1"
    pport = 0
    dport = 26002
    l2_dst = "2c331151213c" #dst_mac
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True,  net_interface="lo", l2_dst=l2_dst)
