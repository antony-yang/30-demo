
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
			"default": "2c331151213c"
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
	"proto": "STP"
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
    if s_block_start(name="frame body"):
        s_byte(name="dsap", value=0x42)
        s_byte(name="ssap", value=0x42)
        s_byte(name="control", value=0x03 ,fuzzable=False)
        if s_block_start(name="spanning"):
            s_word(name='Proto Id', value=0x0000, fuzzable=False)
            s_group(name='Proto Ver ID',values=['\x00', '\x02', '\x03'])
            # s_byte(name='Proto Ver Id', value=0x00, fuzzable=False)
            s_byte(name='bpdu', value=0x00)
            s_byte(name='bpdu flag', value=0x00)
            if s_block_start(name='root id'):
                s_byte(name=' root priority', value=0x80,fuzzable=True)
                s_byte(name='root id exten', value=0x00, fuzzable=True)
                s_static(name='root system mac', value='\x08\xc0\x21\x85\x3f\x90')
                s_block_end('root id')
            s_dword(name='path cost', value=0x00000004, endian=">")
            if s_block_start(name='brige id'):
                s_byte(name='brige priority', value=0x80, fuzzable=True)
                s_byte(name='brige id exten', value=0x01, fuzzable=True)
                s_static(name='brige system mac', value='\x00\xe1\x6d\xfe\x1b\x80')
                s_block_end('brige id')
            s_word(name='port id', value=0x8002, endian=">")
            s_word(name='message age', value=0x0100)
            s_word(name='max age',value=0x1400)
            s_word(name='hello time', value=0x0200)
            s_word(name='forward delay', value=0x0f00)
            s_random(name="body", value="\x00\x00\x00\x00\x00\x00\x00\x00", min_length=8, max_length=1492, num_mutations=10000)
            s_block_end(name="spanning")

        s_block_end(name="frame body")
    s_block_end(name="802.3")

    sess.connect(s_get("ethernet"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "127.0.0.1"
    start_cmds = []
    proc_name = ""
    pport = 0
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface="ens33", dst_mac="0180c2000000")