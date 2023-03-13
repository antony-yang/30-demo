#!/usr/bin/env python

from DongJian import *

param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 110
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
	"proto": "POP3"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    """
    Pop3 protocol fuzz
    """

    session = Session(
        target=Target(
            connection=SocketConnection(target_ip, pport, proto="tcp"),
            # procmon=pedrpc.Client(target_ip, 26002),
            # procmon_options={"start_commands": [start_cmd]},
        ),
        **kwargs
    )

    s_initialize("user")
    s_static("USER")
    s_delim(" ", fuzzable=0)
    s_string("wit_yu@163.com", fuzzable=0)
    s_static("\r\n")

    s_initialize("pass")
    s_static("PASS")
    s_delim(" ", fuzzable=0)
    s_string("cetc30", fuzzable=0)
    s_static("\r\n")
    #
    s_initialize("stat")
    s_static("STAT")
    s_static("\r\n")

    s_initialize("uidl")
    s_static("UIDL")
    s_delim(" ")
    s_int(11111111)
    s_static("\r\n")

    s_initialize("list")
    s_static("LIST")
    s_delim(" ")
    s_int(11111111)
    s_static("\r\n")

    s_initialize("retr")
    s_static("RETR")
    s_static(" ")
    s_int(11111111)
    s_static("\r\n")

    s_initialize("dele")
    s_static("DELE")
    s_static(" ")
    s_int(11111111)
    s_static("\r\n")

    s_initialize("top")
    s_static("TOP")
    s_static(" ")
    s_int(1111111)
    s_delim(" ")
    s_int(11111111)
    s_static("\r\n")

    s_initialize("noop")
    s_static("NOOP")
    s_static("\r\n")

    s_initialize("quit")
    s_static("QUIT")
    s_static("\r\n")



    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.connect(s_get("pass"), s_get("stat"))
    session.connect(s_get("pass"), s_get("list"))
    session.connect(s_get("pass"), s_get("uidl"))
    session.connect(s_get("pass"), s_get("retr"))
    session.connect(s_get("pass"), s_get("dele"))
    session.connect(s_get("pass"), s_get("top"))
    session.connect(s_get("pass"), s_get("noop"))
    session.connect(s_get("pass"), s_get("quit"))

    session.fuzz()


if __name__ == "__main__":
    start_cmds = []
    proc_name = ""
    target_ip = "127.0.0.1"
    pport = 110
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)