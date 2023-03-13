import random

from DongJian import *
import socket
import time

socket.setdefaulttimeout(8)

param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 514
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
	"proto": "Syslog"
}
def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="udp"),
            # procmon=pedrpc.Client(target_ip, dport),
            # procmon_options={"start_commands": start_cmds},
        ),
        **kwargs
    )

    def fixdata(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
        prio = random.randint(0, 7)
        faci = random.randint(0, 23)
        pid = random.randint(0, 65535)
        priority = (prio << 3) | faci
        node.stack[1]._original_value = str(priority)
        node.stack[1]._value = str(priority)
        node.stack[7]._original_value = str(pid)
        node.stack[7]._value = str(pid)


    s_initialize("Syslog")
    prio = random.randint(0, 7)
    faci = random.randint(0, 23)
    pid = random.randint(0, 65535)
    priority = (prio << 3) | faci
    s_static("<")
    s_static(str(priority))
    s_static(">")
    s_static(time.strftime("%b %d %H:%M:%S "))
    s_string(" ", name="hostname or ip", size=20)
    s_string(" ", name="process name", size=20)
    s_static("[")
    s_static(str(pid))
    s_static("]:")
    s_string(" ", name="msg", size=20)

    sess.connect(s_get("Syslog"), callback=fixdata)
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "127.0.0.1"
    pport = 514
    dport = 26002
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
