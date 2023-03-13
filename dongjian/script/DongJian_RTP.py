import struct

from DongJian import *
# from scapy.all import *
import socket
import fcntl
param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 5070
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
		}
	},
	"proto": "RTP"
}

def get_ip_addr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="udp", bind=(get_ip_addr(b"ens33"), 5004)),
            # connection=SocketConnection(host=target_ip, port=pport, proto="udp", ),
        ),
        **kwargs
    )
    s_initialize("RTP")
    with s_block(name="request"):
        s_static(value="\x80", name="ver")
        s_static(value="\x08", name="payload_type")
        s_random(value="\x00\x00", min_length=2, max_length=2, num_mutations=10000, name="sequence_number")
        s_random(value="\x00\x00\x00\x00", min_length=4, max_length=4, num_mutations=10000, name="timestamp")
        s_string(value="\x51\x7c\x36\x4e", name="syn_source_id", size=4)
        s_string(value="\x00", name="payload", size=160)

    sess.connect(s_get("RTP"))
    sess.fuzz()


if __name__=="__main__":
    start_cmds = []
    proc_name=""
    target_ip = "172.16.145.25"
    pport = 5070
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)