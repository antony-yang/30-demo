from DongJian import *
import socket

param={
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 520
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
	"proto": "RIPv1"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="udp"),
        ),
        **kwargs
    )
    s_initialize("RIPv1_request")
    with s_block("v1_request"):
        s_static("\x01")
        s_static("\x01")
        s_static("\x00\x00")
        s_random(value="\x00\x02", min_length=2, max_length=2, num_mutations=60000)
        s_static("\x00\x00")
        s_random(value="\x00\x00\x00\x00", min_length=4, max_length=4, num_mutations=100000)
        s_static("\x00\x00\x00\x00")
        s_static("\x00\x00\x00\x00")
        s_random(value="\x00\x00\x00\x00", min_length=4, max_length=4, num_mutations=100000)

    s_initialize("RIPv1_response")
    with s_block("v1_response"):
        s_static("\x02")
        s_static("\x01")
        s_static("\x00\x00")
        s_random(value="\x00\x02", min_length=2, max_length=2, num_mutations=60000)
        s_static("\x00\x00")
        s_random(value="\x00\x00\x00\x00", min_length=4, max_length=4, num_mutations=100000)
        s_static("\x00\x00\x00\x00")
        s_static("\x00\x00\x00\x00")
        s_random(value="\x00\x00\x00\x00", min_length=4, max_length=4, num_mutations=100000)

    sess.connect(s_get("RIPv1_request"))
    sess.connect(s_get("RIPv1_response"))
    sess.fuzz()


if __name__=="__main__":
    start_cmds = []
    proc_name=""
    target_ip = "127.0.0.1"
    pport = 520
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)