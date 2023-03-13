from DongJian import *
import socket
import fcntl
import uuid
import struct
socket.setdefaulttimeout(8)
import re
from netifaces import ifaddresses, AF_INET, AF_INET6
import platform
import socket
# !/usr/bin/python

# A partial MDNS fuzzer.  Could be made to be a DNS fuzzer trivially
# Charlie Miller <cmiller@securityevaluators.com>
from DongJian import ip_constants

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
			"default": "::1"
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
	"proto": "DHCPv6"
}

def get_ipv6_address(ifname):
    if platform.system() == "Linux":
        try:
            ipv6 = ifaddresses(ifname)[AF_INET6][0]['addr']
            return ipv6.split("%")[0]
            # return ifaddresses(ifname)[AF_INET6][0]['addr']
        except ValueError:
            return None
    else:
        print('您的系统本程序暂时不支持，目前只支持Linux')
        pass

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
    if ipv6_check(target_ip) == 1:
        print("IPv6 Address Correct")
    else:
        target_ip="::1"
        #return target_ip


    sess = Session(
        target=Target(
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l3",
                                        ethernet_proto=0x86dd, l2_dst=transtomac(kwargs["l2_dst"]))
        ),
        **kwargs
    )
    s_initialize("dhcpv6")
    if s_block_start("ipv6"):
        if s_block_start("IPV6_Header"):
            s_static(value='\x60', name='Flow Label')
            s_static(value='\x05\xbd\x44', name='TOS')
            s_size(name='Payload Length', block_name='udpv6_protocol', length=2, inclusive=False, endian='>',
                   fuzzable=False)
            s_static(value='\x11', name='Next Header')
            s_static(value='\x40', name='Hot Limit')
            s_static(value=socket.inet_pton(socket.AF_INET6, get_ipv6_address(kwargs["net_interface"])), name='Source')
            s_static(value=socket.inet_pton(socket.AF_INET6, target_ip), name='Destination')
        s_block_end("IPV6_Header")
        if s_block_start('udpv6_protocol'):
            s_word(value=546, endian='>', fuzzable=False, name='SrcPort')
            s_word(value=pport, endian='>', fuzzable=False, name='DstPort')
            s_size(name='udp length', block_name='udpv6_protocol',
                   length=2, inclusive=False, fuzzable=False, endian='>')
            s_checksum(block_name='udpv6_protocol', algorithm='crc32', length=2, endian='>', fuzzable=False)
            if s_block("udpv6_body"):
                if s_block("dhcpv6"):
                    s_group(name="message type", values=["\x00", "\x01", "\x02",
                                                         "\x03", "\x04", "\x05",
                                                         "\x06", "\x08", "\x90",
                                                         "\x40", "\x60"], default_value="\x01")
                    s_byte(1, fuzzable=True)
                    s_word(1, fuzzable=True)
                    # s_random(name="transaction", min_length=3, max_length=3, fuzzable=True)
                    if s_block("elapsed time"):
                        s_word(name="option", value=1, fuzzable=False,endian=">")
                        s_size(name="len", block_name="data", endian=">", fuzzable=False, inclusive=False, length=2)
                        if s_block("data"):
                            s_random(value="\x0c", min_length=2, max_length=32, name="vendor", num_mutations=1000, fuzzable=True)
                            s_block_end("data")
                        s_block_end("elapsed time")
                    s_repeat("elapsed time", max_reps=5000, step=500)
                s_block_end("dhcpv6")
            s_block_end("udpv6_body")
        s_block_end("udpv6_protocol")
    s_block_end("ipv6")



    sess.connect(s_get("dhcpv6"))
    sess.fuzz()


if __name__ == "__main__":
    start_cmd = ["bgpd"]
    proc_name = ""
    target_ip = "ff02::1:2"
    pport = 547
    dport = 26002
    fuzz(start_cmd, proc_name, target_ip, pport, dport, net_interface="ens33", l2_dst="2c331151213c", script_start=True)