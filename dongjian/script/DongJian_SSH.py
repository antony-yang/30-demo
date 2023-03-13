from DongJian import *
import socket
param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 22
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
	"proto": "SSH"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
        ),
        **kwargs
    )
    s_initialize("SSH")
    with s_block("ssh"):
        s_string("\x00", size=4, name="Packet length")
        s_random(value="\x00", min_length=16, max_length=2000, name="Encrypted Packet", num_mutations=100000)
        s_random(value="\x00", min_length=20, max_length=20, name="Mac", num_mutations=10000)

    sess.connect(s_get("SSH"))
    sess.fuzz()


if __name__ == "__main__":
    start_cmds = []
    proc_name = ""
    target_ip = "127.0.0.1"
    # target_ip = "10.1.0.93"
    pport = 22
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
