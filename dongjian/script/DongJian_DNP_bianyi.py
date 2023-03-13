
from DongJian import *
import math

param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 20000
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
			"default": [""]
		}
	},
	"proto": "DNP"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(target_ip, pport, proto="tcp"),
        ),
        **kwargs
    )

    s_initialize("DNP3")
    s_static("\x05\x64\x16\x02\x04\x00\x03\x00")
    s_random("1c4300000000000000000000000000000000ffff00ffff", min_length=23, max_length=23)

    sess.connect(s_get("DNP3"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "172.16.145.25"
    start_cmds = []
    proc_name = ""
    pport = 20000
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
