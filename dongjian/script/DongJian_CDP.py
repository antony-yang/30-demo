
from DongJian import *
import uuid
import socket
import fcntl
import struct

socket.setdefaulttimeout(8)

param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 0
		},
		"pport": {
			"ness": 0,
			"default": 26002
		},
		"proc_name": {
			"ness": 0,
			"default": ""
		},
		"target_ip": {
			"ness": 0,
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
	"proto": "CDP"
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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', ifname[:15])
    )[20:24]


def fuzz(start_cmds, proc_name, target_ip, pport, dport,  *args, **kwargs):
    try:
        kwargs["net_interface"]
    except KeyError as e:
        print("lack of parameter net_interface")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l2"),
        ),
        **kwargs
    )
    s_initialize("cdp")
    s_block_start(name="802.3")
    s_static(value="\x01\x00\x0c\xcc\xcc\xcc", name="dst")
    s_static(value=get_mac_addr(), name="src")
    s_size(name="size", block_name="frame body", fuzzable=False, endian=">", inclusive=False, length=2)
    s_block_start(name="frame body")
    s_static(name="dsap", value="\xaa")
    s_static(name="ssap", value="\xaa")
    s_static(name="cntl", value="\x03")
    s_static(name="org code", value="\x00\x00\x0c")
    s_static(name="pid", value="\x20\x00")
    s_block("cdp_body")
    s_static(name="ver", value="\x02")
    s_static(name="TTL", value="\xb4")
    s_checksum(block_name="cdp_body", length=2, endian=">", fuzzable=False, name="checksum", algorithm="ipv4")

    s_block("tlv_device_id")
    s_word(name="type1", endian=">", value=0x0001, fuzzable=False)
    s_size(name="length1", block_name="tlv_device_id", length=2, endian=">", fuzzable=False, inclusive=False)
    s_random(value="switch", name="device_id", max_length=32, min_length=6, step=2, num_mutations=10000)
    s_block_end("tlv_device-id")

    s_block("tlv_soft_ver")
    s_word(name="type2", endian=">", value=0x0005, fuzzable=False)
    s_size(name="length2", block_name="tlv_soft_ver", length=2, endian=">", fuzzable=False, inclusive=False)
    s_random(value="cisco1", name="soft_ver", max_length=32, min_length=6, step=2, num_mutations=10000)
    s_block_end("tlv_soft_ver")

    s_block("tlv_platform")
    s_word(name="typ3", endian=">", value=0x0006, fuzzable=False)
    s_size(name="length3", block_name="tlv_platform", length=2, endian=">", fuzzable=False, inclusive=False)
    s_random(value="cisco WS-XXXX-XX", name="platform", max_length=32, min_length=16, step=2, num_mutations=10000)
    s_block_end("tlv_platform")

    s_block("tlv_address")
    s_word(name="typ4", endian=">", value=0x0002, fuzzable=False)
    s_size(name="length4", block_name="tlv_address", length=2, endian=">", fuzzable=False, inclusive=False)
    s_dword(value=0, name="address", endian=">")
    s_block_end("tlv_address")

    s_block("tlv_port_id")
    s_word(name="type5", endian=">", value=0x0003, fuzzable=False)
    s_size(name="length5", block_name="tlv_port_id", length=2, endian=">", fuzzable=False, inclusive=False)
    s_random(value="interface 0/2", name="send", max_length=33, min_length=13, step=2, num_mutations=10000)
    s_block_end("tlv_port_id")

    s_block("tlv_capabilities")
    s_word(name="type6", endian=">", value=0x0004, fuzzable=False)
    s_size(name="length6", block_name="tlv_capabilities", length=2, endian=">", fuzzable=False, inclusive=False)
    s_dword(value=0x00000028, name="cap", endian=">")
    s_block_end("tlv_capabilities")

    s_block("tlv_hello")
    s_word(name="type7", endian=">", value=0x0008, fuzzable=False)
    s_size(name="length7", block_name="tlv_hello", length=2, endian=">", fuzzable=False, inclusive=False)
    s_random(value="0"*8+"1"*8+"0"*8+"1"*8, name="hellobody", max_length=32, min_length=32, num_mutations=10000)
    s_block_end("tlv_hello")

    s_block("tlv_vtp")
    s_word(name="type8", endian=">", value=0x0009, fuzzable=False)
    s_size(name="length8", block_name="tlv_vtp", length=2, endian=">", fuzzable=False, inclusive=False)
    s_block_end("tlv_vtp")

    s_block("tlv_vlan")
    s_word(name="type9", endian=">", value=0x000a, fuzzable=False)
    s_size(name="length9", block_name="tlv_vlan", length=2, endian=">", fuzzable=False, inclusive=False)
    s_word(value=1, name="nvlan", endian=">")
    s_block_end("tlv_vlan")

    s_block("tlv_duplex")
    s_word(name="type10", endian=">", value=0x000b, fuzzable=False)
    s_size(name="length10", block_name="tlv_duplex", length=2, endian=">", fuzzable=False, inclusive=False)
    s_byte(value=0, name="duplex")
    s_block_end("tlv_duplex")

    s_block("tlv_tbitmap")
    s_word(name="type11", endian=">", value=0x0012, fuzzable=False)
    s_size(name="length11", block_name="tlv_tbitmap", length=2, endian=">", fuzzable=False, inclusive=False)
    s_byte(value=0, name="tbitmap")
    s_block_end("tlv_tbitmap")

    s_block("tlv_ucos")
    s_word(name="type12", endian=">", value=0x0013, fuzzable=False)
    s_size(name="length12", block_name="tlv_ucos", length=2, endian=">", fuzzable=False, inclusive=False)
    s_byte(value=0, name="ucos")
    s_block_end("tlv_ucos")

    s_block("tlv_maddr")
    s_word(name="type13", endian=">", value=0x0016, fuzzable=False)
    s_size(name="length13", block_name="tlv_maddr", length=2, endian=">", fuzzable=False, inclusive=False)
    s_dword(value=0x00000000, name="num_of_maddr", endian=">")
    s_block_end("tlv_mddr")

    s_block("tlv_power")
    s_word(name="type14", endian=">", value=0x001a, fuzzable=False)
    s_size(name="length14", block_name="tlv_power", length=2, endian=">", fuzzable=False, inclusive=False)
    s_word(name="req_id", value=0, endian=">")
    s_word(name="m_id", value=1, endian=">")
    s_dword(value=0x00000000, name="pa", endian=">")
    s_dword(value=0xffffffff, name="pa2", endian=">")
    s_block_end("tlv_power")

    s_block_end("cdp_body")

    s_block_end(name="frame body")
    s_block_end(name="802.3")

    sess.connect(s_get("cdp"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "10.38.4.16"
    start_cmds = []
    proc_name = ""
    pport = 0
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, net_interface="ens38", script_start=True)