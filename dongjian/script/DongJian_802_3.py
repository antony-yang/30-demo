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
			"default": 26002
		},
		"pport": {
			"ness": 0,
			"default": 0
		},
		"dst_mac": {
			"ness": 1,
			"default": "ffffffffffff"
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
	"proto": "802_3"
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


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        kwargs["net_interface"]
        kwargs["dst_mac"]
    except KeyError as e:
        print("lack of parameter net_interface")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l2"),
        ),
        **kwargs
    )
    s_initialize("ethernet")
    s_block_start(name="802.3")
    s_static(value=transtomac(kwargs["dst_mac"]), name="dst")
    s_static(value=get_mac_addr(), name="src")
    s_size(name="size", block_name="frame body", fuzzable=False, endian=">", inclusive=False, length=2)
    s_block_start(name="frame body", group="type")
    s_byte(name="dsap", value=0xaa)
    s_byte(name="ssap", value=0xaa)
    s_word(name="cntl", value=0x0000)
    s_static(name="org code", value="\x00\x00\x00")
    s_group(values=["\x06\x00", "\x06\x60", "\x06\x61", "\x08\x00", "\x08\x01", "\x08\x02", "\x08\x03", "\x08\x04",
                    "\x08\x05", "\x08\x06", "\x08\x08", "\x65\x59", "\x80\x35", "\x80\x37", "\x80\x9B", "\x80\xD5",
                    "\x80\xF3", "\x81\x00", "\x81\x37", "\x81\x4C", "\x86\xDD", "\x88\x09", "\x88\x0B", "\x88\x0C",
                    "\x88\x47", "\x88\x48", "\x88\x63", "\x88\x64", "\x88\xBB", "\x88\xCC", "\x8E\x88", "\x90\x00",
                    "\x91\x00", "\x92\x00"], name="type", default_value="\x08\x00")
    s_random(name="body", value="\x00", min_length=38, max_length=1492, num_mutations=10000)
    s_block_end(name="frame body")
    s_block_end(name="802.3")

    sess.connect(s_get("ethernet"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "10.38.4.16"
    start_cmds = []
    proc_name = ""
    pport = 0
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface="ens33", dst_mac="ffffffffffff")