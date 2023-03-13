#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8

from DongJian import *

"""
   HELLO MAIL RCPT DATA RSET VRFY EXPN HELP NOOP QUIT
"""
param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 25
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
	"proto": "SMTP"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    session = Session(
        target=Target(connection=SocketConnection(target_ip, pport, proto="tcp")),
        **kwargs
    )

    s_initialize("Login-SMTP")
    with s_block("Auth"):
        s_group("Login", ["HELO", "EHLO"])
        if s_block_start("body", group="Login"):
            s_delim(" ", name="space1")
            s_string("XAXA", name="Fuzz1")
            s_static("\r\n", name="Fuzz-CRFL")
        s_block_end()

    s_initialize("Command-SMTP")
    with s_block("Commands"):
        s_group("Command", ["EXPN", "MAIL FROM:", "ETRN", "HELP", "RCTP TO:"])
        if s_block_start("body", group="Command"):
            s_delim(" ", name="space1")
            s_string("XAXAX", name="fuzz1")
            s_static("\r\n", name="SMTP-CRFT")
        s_block_end()

    s_initialize("Other-SMTP")
    with s_block("Others"):
        s_group("Other", ["VRFY", "RSET", "NOOP", "QUIT"])
        if s_block_start("body", group="Other"):
            s_delim(" ")
            s_static("\r\n")
        s_block_end()

    s_initialize("DATA")
    s_static("data")
    s_string("aaa", max_len=1500, padding=b"u\0000", fuzzable=False)
    s_static("\r\n")

    session.connect(s_get("Login-SMTP"))
    session.connect(s_get("Login-SMTP"), s_get("Command-SMTP"))
    session.connect(s_get("Login-SMTP"), s_get("DATA"))
    session.connect(s_get("Command-SMTP"), s_get("Other-SMTP"))
    session.fuzz()


if __name__ == "__main__":
    start_cmds = []
    proc_name = ""
    target_ip = "127.0.0.1"
    pport = 25
    dport = 0
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
