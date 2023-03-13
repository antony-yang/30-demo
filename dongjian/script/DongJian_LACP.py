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
    s_static(value="\x01\x80\xc2\x00\x00\x02", name="dst")
    s_static(value=get_mac_addr(), name="src")
    s_static(value="\x88\x09", name="Type")
    s_block_start(name="frame body")

    s_static(value="\x01", name="subtype")
    s_static(value="\x01", name="ver")

    s_block("actor")
    s_static(value="\x01", name="type_actor")
    # s_size(block_name="actor", length=1, fuzzable=False, inclusive=True, endian=">", name="size_actor", math= lambda x:x-1)
    s_static(name="size_actor", value="\x14")
    s_bytes(value=b"00", size=2, name="actor_system_priority")
    s_bytes(value=b"000000", size=6, name="actor_system")
    s_bytes(value=b"00", size=2, name="actor_key")
    s_bytes(value=b"00", size=2, name="actor_port_priority")
    s_bytes(value=b"00", size=2, name="actor_port")
    s_bytes(value=b"0", size=1, name="actor_state")
    s_bytes(value=b"000", size=3, name="actor_reserved", fuzzable=False)
    s_block_end()

    s_block("partner")
    s_static(value="\x02", name="type_partner")
    s_static(name="size_partner", value="\x14")
    s_bytes(value=b"00", size=2, name="partner_system_priority")
    s_bytes(value=b"000000", size=6, name="partner_system")
    s_bytes(value=b"00", size=2, name="partner_key")
    s_bytes(value=b"00", size=2, name="partner_port_priority")
    s_bytes(value=b"00", size=2, name="partner_port")
    s_bytes(value=b"0", size=1, name="partner_state")
    s_bytes(value=b"000", size=3, name="partner_reserved", fuzzable=False)
    s_block_end()

    s_block("collector")
    s_static(value="\x03", name="type_collector")
    s_static(name="size_collector", value="\x10")
    s_bytes(value=b"00", size=2, name="collector_max_delay")
    s_bytes(value=b"\x00", padding=b"\x00", size=12, name="collector_reserved", fuzzable=False)
    s_block_end()

    s_block("terminator")
    s_static(value="\x00", name="type_terminator")
    s_static(name="size_terminator", value="\x00")
    s_bytes(value=b"\x00", padding=b"\x00", size=50, name="terminator_reserved", fuzzable=False)
    s_block_end()

    s_block_end(name="frame body")
    s_block_end(name="802.3")

    sess.connect(s_get("ethernet"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = ""
    start_cmds = []
    proc_name = ""
    pport = 0
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface="ens33")