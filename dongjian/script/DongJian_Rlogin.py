
from DongJian import *


param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 513
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
	"proto": "rlogin"
}

def SendAbortCmd(target, fuzz_data_logger, session, sock):
    target.send(b"\x01\x0a")
    pass

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
        ),
        **kwargs
    )

    s_initialize(name="fuzz start Handshake")
    s_static("\x00")
    s_string("\x00", max_len=1459)

    s_initialize(name="normal start Handshake")
    s_static("\x00")

    s_initialize(name="Terminal Info")
    s_static("\xff\xff", name = "Magic Cookie")
    s_string("ss", max_len = 2, name = "Windows size marker")
    s_word(0x24, full_range = True, name = "Rows")
    s_word(0x80, full_range = True, name = "Columns")
    s_word(0, full_range = True, name="X Pixels")
    s_word(0, full_range = True, name="Y Pixels")

    s_initialize(name="Data")
    s_string("/x0d", max_len=1460)

    sess.connect(s_get("fuzz start Handshake"))
    sess.connect(s_get("Terminal Info"))
    sess.connect(s_get("Data"))

    sess.connect(s_get("normal start Handshake"))
    sess.connect(s_get("normal start Handshake"), s_get("Data"))
    sess.connect(s_get("normal start Handshake"), s_get("Terminal Info"))
    sess.connect(s_get("Terminal Info"), s_get("Data"))

    sess.fuzz()


if __name__ == "__main__":

    target_ip = "127.0.0.1"
    start_cmds = []
    proc_name = ""
    pport = 513
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
