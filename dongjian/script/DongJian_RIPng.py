from DongJian import *
import random
import socket
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
			"default": "fe80::57a7:e3e3:acd9:21ce"
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
	"proto": "RIPng"
}

##############################
#          RFC 2080          #
##############################

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

    sess = Session(
        target=Target(
            connection=SocketConnection(host=net_interface, proto="raw-l3", ethernet_proto=0x86dd, l2_dst=transtomac(l2_dst)),
        ),
        **kwargs
    )

    ipv6_addr = ifaddresses(net_interface)[AF_INET6][0]['addr'].split("%")[0]
    s_initialize("RIPng Request")
    if s_block_start("IPv6"):
        if s_block_start("IPV6_Header"):
            s_static(value='\x60', name='Flow Label')
            s_static(value='\x05\xbd\x44', name='TOS')
            s_size(name='Payload Length', block_name='udpv6_protocol', length=2, inclusive=False, endian='>',
                   fuzzable=False)
            s_static(value='\x11', name='Next Header')
            s_static(value='\x01', name='Hot Limit')
            s_string(socket.inet_pton(AF_INET6, ipv6_addr), size=16, encoding="utf8", name="ipv6.src", fuzzable=False)
            s_string(socket.inet_pton(AF_INET6, target_ip), size=16, encoding="utf8", name="ipv6.dst", fuzzable=False)
        s_block_end("IPV6_Header")
        if s_block_start('udpv6_protocol'):
            # s_word(value=521, endian='>', fuzzable=True, name='SrcPort')
            s_static("\x02\x09", name='SrcPort')
            # s_word(value=521, endian='>', fuzzable=True, name='DstPort')
            s_static("\x02\x09", name='DstPort')
            s_size(name='udp length', block_name='udpv6_protocol', length=2, inclusive=False, fuzzable=False, endian='>')
            s_checksum(block_name='udpv6_protocol', algorithm='crc32', length=2, endian='>',fuzzable=False)
            # s_string(value='11111', name='Data', padding=b"\u0000", max_len=1500)
            if s_block_start("RIPng"):
                s_static("\x01", name="command")
                s_static("\x01", name="version")
                s_static("\x00\x00")
                if random.random()>0.5:
                    s_random("\x00"*16, min_length=16, max_length=16, name="IPv6 next hop")
                    s_static("\x00\x00\x00\xff", name="flag")
                s_random("\x01"*16, min_length=16, max_length=16, name="IPv6 prefix")
                s_string("\x00\x00", name="route tag", size=2, encoding="utf8")
                s_static("\x00", name="prefix lex")
                s_group(name="metric", values=["\x10","\x0f","\x0e","\x0d","\x0c","\x0b","\x0a","\x09","\x08","\x07","\x06","\x05","\x04","\x03","\x02","\x01"])
            s_block_end("RIPng")
        s_block_end(name='udpv6_protocol')
    s_block_end("IPv6")

    s_initialize("RIPng Response")
    if s_block_start("IPv6"):
        if s_block_start("IPV6_Header"):
            s_static(value='\x60', name='Flow Label')
            s_static(value='\x05\xbd\x44', name='TOS')
            s_size(name='Payload Length', block_name='udpv6_protocol', length=2, inclusive=False, endian='>',
                   fuzzable=False)
            s_static(value='\x11', name='Next Header')
            s_static(value='\x01', name='Hot Limit')
            s_string(socket.inet_pton(AF_INET6, ipv6_addr), size=16, encoding="utf8", name="ipv6.src", fuzzable=False)
            s_string(socket.inet_pton(AF_INET6, target_ip), size=16, encoding="utf8", name="ipv6.dst", fuzzable=False)
        s_block_end("IPV6_Header")
        if s_block_start('udpv6_protocol'):
            # s_word(value=521, endian='>', fuzzable=True, name='SrcPort')
            s_static("\x02\x09", name='SrcPort')
            # s_word(value=521, endian='>', fuzzable=True, name='DstPort')
            s_static("\x02\x09", name='DstPort')
            s_size(name='udp length', block_name='udpv6_protocol', length=2, inclusive=False, fuzzable=False,
                   endian='>')
            s_checksum(block_name='udpv6_protocol', algorithm='crc32', length=2, endian='>', fuzzable=False)
            # s_string(value='11111', name='Data', padding=b"\u0000", max_len=1500)
            if s_block_start("RIPng"):
                s_static("\x02", name="command")
                s_static("\x01", name="versiens33on")
                s_static("\x00\x00")
                # s_string("\x01" * 16, size=16, name="IPv6 prefix", encoding="utf8")
                s_random("\x01" * 16, min_length=16, max_length=16, name="IPv6 prefix")
                s_string("\x00\x00", name="route tag", size=2, encoding="utf8")
                s_static("\x00", name="prefix lex")
                s_group(name="metric",
                        values=["\x10", "\x0f", "\x0e", "\x0d", "\x0c", "\x0b", "\x0a", "\x09", "\x08", "\x07", "\x06",
                                "\x05", "\x04", "\x03", "\x02", "\x01"])
            s_block_end("RIPng")
        s_block_end(name='udpv6_protocol')
    s_block_end("IPv6")

    sess.connect(s_get('RIPng Request'))
    sess.connect(s_get('RIPng Response'))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "fe80::57a7:e3e3:acd9:21ce"
    start_cmds = []
    proc_name = ""
    pport = 0
    dport= 0
    net_interface = "lo"
    l2_dst = "2c331151213c"
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface = net_interface, l2_dst = l2_dst)
