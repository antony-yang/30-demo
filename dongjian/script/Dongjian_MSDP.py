from DongJian import *
import socket

socket.setdefaulttimeout(8)

param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 639
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
	"proto": "MSDP"
}


def fuzz(start_cmds, proc_name, target_ip, pport, dport,  *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
            # procmon=pedrpc.Client(target_ip, dport),
            # procmon_options={"start_commands": start_cmds},
        ),
        **kwargs
    )

    def totallen(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
        pass
        node.stack[1]._original_value = str(len(node.original_value))
        node.stack[1]._value = str(len(node.original_value))


    s_initialize("SACONTROL")
    s_static("\x01", name="type")
    s_static("\x00\x00", name="length")
    s_static("\x01", name="entry_count")
    s_string("\x01\x11\x22\x33", name="rp_adress")
    with s_block("entry"):
        s_static("\x00\x00\x00\x20", name="reversed")
        s_static("\x18", name="sprefix_len")
        s_string("\x70\x66\x32\x58", name="group_address")
        s_string("\x55\x66\x51\x44", name="source_address")

    s_initialize("KEEPALIVE")
    s_static("\x04", name="type")
    s_static("\x00\x03", name="length")
    s_static("\x00\x00\x00", name="content")

    sess.connect(s_get("SACONTROL"), callback=totallen)
    sess.connect(s_get("SACONTROL"), s_get("KEEPALIVE"), callback=totallen)
    sess.fuzz()

if __name__ == "__main__":
    target_ip = "172.16.145.25"
    pport = 639
    dport = 26002
    start_cmds = [""]
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
