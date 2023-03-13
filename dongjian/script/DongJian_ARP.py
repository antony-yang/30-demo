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
		"dst_ip": {
			"ness": 1,
			"default": "127.0.0.1"
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
	"proto": "ARP"
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
        kwargs["dst_ip"]
    except KeyError as e:
        print("lack of parameter net_interface")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l2"),
        ),
        **kwargs
    )
    s_initialize("ethernetII")
    s_block_start(name="ARP")
    s_static(value="\xff\xff\xff\xff\xff\xff", name="dst")
    s_static(value=get_mac_addr(), name="src")
    s_static(value="\x08\x06", name="type")
    s_string(value="\x00\x01", name="hard_type", max_len=2)
    s_static("\x08\x00", "protocol_type")
    s_string(value="\x06", name="hardware_size", max_len=1)
    s_string(value="\x04", name="protocol_size", max_len=1)
    s_group(name="op_code", values=["\x00\x01", "\x00\02"])
    s_static(get_mac_addr(), "sender_mac")
    s_static(value=get_ip_addr(bytes(kwargs["net_interface"], "utf-8")), name="sender_ip") #local ip address
    s_string(value="", name="target_mac", max_len=6, padding="\x00")
    s_static(value=socket.inet_aton(kwargs["dst_ip"]), name="target_ip")
    s_block_end(name="ARP")
    sess.connect(s_get("ethernetII"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "172.16.145.25"
    start_cmds = []
    proc_name = ""
    pport = 0
    dport=26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, net_interface="ens33", dst_ip="172.16.145.25", script_start=True)