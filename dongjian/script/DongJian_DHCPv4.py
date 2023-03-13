from DongJian import *
import socket
import fcntl
import uuid
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
			"default": 67
		},
		"l2_dst": {
			"ness": 1,
			"default": "ffffffffffff"
		},
		"proc_name": {
			"ness": 0,
			"default": ""
		},
		"target_ip": {
			"ness": 1,
			"default": "255.255.255.255"
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
	"proto": "DHCPv4"
}

def get_mac_addr():  # get mac address and trans it into hex byte format
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


def TransToInt(c):  # trans a char to a int
    if '0' <= c <= '9':
        return int(c)
    if 'a' <= c <= 'z':
        return ord(c) - ord('a') + 10
    return 0


def get_ip_addr(ifname):  # get interface's ip address, parameter ifname only accept bytes(do not accept str class)
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

prl = ["\x37","\x14","\x01","\x03","\x06","\x0f","\x1c","\x21","\x2c","\x42","\x43","\x79","\x8d","\x8e","\x8f","\x91","\x92","\x93","\x94","\x95","\x96","\xb8"]

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        kwargs["net_interface"]  # iframe
        kwargs["l2_dst"]  # router's mac address
    except KeyError as e:
        print("lack of parameter")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l3",
                                        ethernet_proto=0x0800, l2_dst=transtomac(kwargs["l2_dst"]))
        ),
        **kwargs
    )
    s_initialize("dhcpv4")
    if s_block_start("ipv4"):
        if s_block_start("ipv4_header"):
            s_static(b"\x45", "ver")
            s_static(b"\x00", "TOS")
            ###########################################
            s_size(name="total length", block_name="ipv4", length=2, inclusive=False, fuzzable=False, endian=">")
            s_static("\x0c\x08", "Identification")
            s_static("\x40", "Flags")
            s_static("\x00", "offset")
            s_byte(value=0x80, name="ttl", endian=">")
            s_static("\x11", "protocol")
            s_checksum(name="header checksum", block_name="ipv4_header", length=2, algorithm="ipv4", fuzzable=False, endian=">")
            if s_block("ipv4_src"):
                s_static("\x00" * 4, "src_ip") #get_ip_addr(kwargs["net_interface"])
            s_block_end()
            if s_block("ipv4_dst"):
                s_static(socket.inet_aton(target_ip), "dst_ip")
            s_block_end()
        s_block_end("ipv4_header")
        if s_block_start(name="udp"):
            s_static(name="src_port", value="\x00\x44")
            s_static(name="dst_port", value="\x00\x43")
            ###########################################
            s_size(block_name="udp", inclusive=False, endian=">", length=2, fuzzable=False, name="udp_length")
            s_checksum(block_name="udp_body", length=2, endian=">", fuzzable=False, algorithm="udp", ipv4_src_block_name="ipv4_src", ipv4_dst_block_name="ipv4_dst")
            if s_block("udp_body"):
                if s_block("dhcp"):
                    s_group(name="op", values=["\x01", "\x02"])
                    s_group(name="htype", values=["\x01"])
                    s_static(name="hlen", value="\x06")
                    s_static(name="hops", value="\x00")
                    s_dword(name="xid", endian=">", value=1)
                    s_word(name="secs", endian=">", value=123)
                    s_bit_field(name="flags", width=16, value=0)
                    s_bytes(name="ciaddr", size=4, value=get_ip_addr(bytes(kwargs["net_interface"], "utf-8")))
                    s_bytes(name="yiaddr", size=4, value=b"\x00" * 4)
                    s_bytes(name="siaddr", size=4, value=b"\x00" * 4)
                    s_bytes(name="giaddr", size=4, value=b"\x00" * 4)
                    s_bytes(name="chaddr", size=6, value=get_mac_addr(), fuzzable=False)
                    s_bytes(name="chaddr_padding", size=10, value=b"\x00"*10, fuzzable=False)
                    s_bytes(name="s_name", size=64, value=b"\x00" * 64)
                    s_bytes(name="file", size=128, value=b"\x00" * 128)
                    s_static(name="dhcp_magic_cookie", value="\x63\x82\x53\x63")

                    if s_block("message_type"):
                        s_static(name="discover", value="\x35")
                        s_size(block_name="message_body", endian=">", fuzzable=False, inclusive=False, name="length1", length=1)
                        s_block("message_body")
                        s_static("\x01")
                        s_block_end()
                    s_block_end()
                    if s_block("client_identifier"):
                        s_static(name="ci", value="\x3d")
                        s_size(block_name="ci_body", endian=">", fuzzable=False, inclusive=False, name="length2", length=1)
                        s_block("ci_body")
                        s_static("\x01")
                        s_random(value="\xff"*6, min_length=6, max_length=6, num_mutations=1000, name="mac_addr")
                        s_block_end()
                    s_block_end()
                    if s_block("mdms"):
                        s_static(name="_mdms", value="\x39")
                        s_size(block_name="mdms_body", endian=">", fuzzable=False, inclusive=False, name="length3", length=1)
                        s_block("mdms_body")
                        s_word(value=1464, endian=">", name="max_dhcp_size")
                        s_block_end()
                    s_block_end()
                    if s_block("vender_ci"):
                        s_static(name="vci", value="\x3c")
                        s_size(block_name="vci_body", endian=">", fuzzable=False, inclusive=False, name="length4", length=1)
                        s_block("vci_body")
                        s_random(value="\x0c"*32, min_length=32, max_length=32, name="vendor", num_mutations=1000)
                        s_block_end()
                    s_block_end()
                    if s_block("prl"):
                        s_static(name="para_req_list", value="\x37")
                        s_size(block_name="prl_body", endian=">", fuzzable=False, inclusive=False, name="length5", length=1)
                        s_block("prl_body")
                        s_group(name="1",values=prl, default_value=prl[0])
                        s_group(name="2", values=prl, default_value=prl[1])
                        s_group(name="3", values=prl, default_value=prl[2])
                        s_group(name="4", values=prl, default_value=prl[3])
                        s_group(name="5", values=prl, default_value=prl[4])
                        s_group(name="6", values=prl, default_value=prl[5])
                        s_group(name="7", values=prl, default_value=prl[6])
                        s_group(name="8", values=prl, default_value=prl[7])
                        s_group(name="9", values=prl, default_value=prl[8])
                        s_group(name="10", values=prl, default_value=prl[9])
                        s_group(name="11", values=prl, default_value=prl[10])
                        s_group(name="12", values=prl, default_value=prl[11])
                        s_group(name="13", values=prl, default_value=prl[12])
                        s_group(name="14", values=prl, default_value=prl[13])
                        s_group(name="15", values=prl, default_value=prl[14])
                        s_group(name="16", values=prl, default_value=prl[15])
                        s_group(name="17", values=prl, default_value=prl[16])
                        s_group(name="18", values=prl, default_value=prl[17])
                        s_group(name="19", values=prl, default_value=prl[18])
                        s_group(name="20", values=prl, default_value=prl[19])
                        s_block_end()
                    s_block_end()
                    if s_block("end"):
                        s_static(name="_end", value="\xff")
                    s_block_end()

                s_block_end("dhcp")
            s_block_end("udp_body")
        s_block_end("udp")
    s_block_end("ipv4")

    sess.connect(s_get("dhcpv4"))
    sess.fuzz()


if __name__ == "__main__":
    start_cmd = ["bgpd"]
    proc_name = ""
    target_ip = "255.255.255.255"
    pport = 67
    dport = 26002
    fuzz(start_cmd, proc_name, target_ip, pport, dport, script_start=True, net_interface="ens33", l2_dst="ffffffffffff")
