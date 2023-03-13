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
			"default": 69
		},
		"bind_ip": {
			"ness": 1,
			"default": "0.0.0.0"
		},
		"bind_port": {
			"ness": 1,
			"default": 4444
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
	"proto": "TFTP"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        kwargs["bind_ip"]
        kwargs["bind_port"]
    except KeyError as e:
        print("key error")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="udp", bind=(kwargs["bind_ip"], kwargs["bind_port"])),
            # procmon=pedrpc.Client(target_ip, dport),
            # procmon_options={"start_commands": start_cmds},
        ),
        **kwargs
    )

    s_initialize("READ")
    s_string("\x00\x01", name="opcode", fuzzable=False)
    s_string("", name="filename")
    with s_block(name="modeblk", group="mode"):
        s_byte(0x00)
        s_group("mode", ["netascii", "octet", "mail"])
        s_byte(0x00)

    s_initialize("WRITE")
    s_string("\x00\x02", name="opcode", fuzzable=False)
    s_string("", name="filename")
    s_byte(0x00)
    s_group("mode", ["netascii", "octet", "mail"])
    s_byte(0x00)

    s_initialize("DATA")
    s_string("\x00\x03", name="opcode", fuzzable=False)
    s_byte(0, name="block_index")
    s_string("", name="data")

    s_initialize("ACK")
    s_string("\x00\x04", name="opcode", fuzzable=False)
    s_string("\x00", name="block_index")

    sess.connect(s_get("READ"))
    sess.connect(s_get("READ"), s_get("ACK"))
    sess.connect(s_get("ACK"), s_get("WRITE"))
    sess.connect(s_get("WRITE"), s_get("DATA"))
    sess.connect(s_get("DATA"))
    sess.fuzz()

    #sess.fuzz_single_node_by_path(["READ"])
    #sess.fuzz_single_node_by_path(["READ", "ACK"])
    #sess.fuzz_single_node_by_path(["WRITE"])
    #sess.fuzz_single_node_by_path(["WRITE", "DATA"])
    #sess.fuzz_single_node_by_path(["WRITE", "DATA", "ACK"])


if __name__ == "__main__":
    target_ip = "127.0.0.1"
    pport = 69
    dport = 26002
    start_cmds = ["C:\\Program Files\\tftpd\\tftpd64.exe"]
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, bind_ip="0.0.0.0", bind_port=4444)
