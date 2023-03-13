from DongJian import *
import socket
socket.setdefaulttimeout(1)
param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 2425
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
			"default": [
			]
		}
	},
	"proto": "ipmsg"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="udp", bind=("0.0.0.0", 2425)),
        ),
        **kwargs
    )

    s_initialize("ipmsg")
    s_static(name="version", value="1_1bt4_0#128#309C234EB654#0#0#0#311c#9")
    s_static(name="1", value=":")
    s_static(name="num", value="1593021972")
    s_static(name="2", value=":")
    s_static(name="name", value="administrator")
    s_static(name="3", value=":")
    s_static(name="mechine", value="DESKTOP-EVBH2KI")
    s_static(name="4", value=":")
    s_static(name="cmd", value="121")
    s_static(name="5", value=":")
    s_static(name="end", value="\x00")

    cmds = ['288', '0', '1', '2', '3', '4', '16', '17', '18', '19', '20', '22', '24', '32', '33', '48', '49',
            '114', '115', '120', '121', '256', '472', '512', '984', '65536', '131072', '2097344',
            '4194592', '6291458', '6291459']
    s_initialize("ipmsg2")
    with s_block(name='test', group='cmds'):
        s_static(name="version2", value="1_1bt4_0#128#309C234EB654#0#0#0#311c#9")
        s_static(name="12", value=":")
        s_static(name="num2", value="1593021973")
        s_static(name="22", value=":")
        s_string(name="name2", value="administrator")
        s_static(name="32", value=":")
        s_string(name="mechine2", value="DESKTOP-EVBH2KI")
        s_static(name="42", value=":")
        # s_static(name="cmd2", value="288")
        s_group(name='cmds',values=cmds)
        s_static(name="52", value=":")
        s_string(name="extra", value="\x00")
        # s_static(name="end2", value="\x00")

    # sess.connect(s_get("ipmsg"))
    # sess.connect(s_get("ipmsg"), s_get("ipmsg2"))
    # sess.fuzz_single_node_by_path(["ipmsg", "ipmsg2"])
    sess.connect(s_get("ipmsg2"))
    sess.fuzz()

if __name__=="__main__":
    target_ip = "10.38.4.112"
    pport = 2425
    dport = 26002
    start_cmds = ["H:/FeiQ.exe"]
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)