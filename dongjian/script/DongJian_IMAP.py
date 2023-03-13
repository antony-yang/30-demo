#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8


from DongJian import *

"""
IMAP Protocol Commands:
Any:CAPABILITY NOOP LOGOUT
Un Authentication:STARTTLS AUTHENTICATE LOGIN
Authentication:SELECT EXAMINE CREATE DELETE RENAME SUBSCRIBE UNSUBSCRIBE LIST LSUB STATUS APPEND 
Selected:CHECK CLOSE EXPUNGE SEARCH FETCH STORE COPY UID 
"""
param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 143
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
	"proto": "IMAP"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    session = Session(
        target=Target(
            connection=SocketConnection(target_ip, pport, proto="tcp"),
            # procmon=pedrpc.Client(target_ip, 26002),
            # procmon_options={"start_commands": [start_cmd]},
        ),
        **kwargs
    )

    # Any#
    s_initialize("capability")
    s_string("1111", fuzzable=True, max_len=4)
    s_static("CAPABILITY")
    s_static("\r\n")

    s_initialize("noop")
    s_string("sadf", max_len=4)
    s_static("NOOP")
    s_static("\r\n")

    s_initialize("logout")
    s_string("sdfd", max_len=4)
    s_static("LOGOUT")
    s_static("\r\n")

    # Un Authentication#

    s_initialize("starttls")
    s_string("ahes", max_len=4)
    s_static("STARTTLS")
    s_static("\r\n")

    s_initialize("authenticate")
    s_string("l30z", max_len=4)
    s_static("AUTHENTICATE")
    s_static("\r\n")

    s_initialize("login")
    s_string("b001 ", fuzzable=True, max_len=4)
    s_static("LOGIN wit_yu@163.com cetcsc30")
    s_static("\r\n")

    # Authentication#

    s_initialize("select")
    s_string("0981", max_len=4)
    s_static("SELECT")
    s_delim(" ")
    s_static("wit_yu@163.com")
    s_static("\r\n")

    s_initialize("examine")
    s_string("0269", max_len=4)
    s_static("EXAMINE")
    s_delim(" ")
    s_static("wit_yu@163.com")
    s_static("\r\n")

    s_initialize("create")
    s_string("0ox1", max_len=4)
    s_static("CTEARE")
    s_delim(" ")
    s_static("wit01@163.com cetcsc003")
    s_static("\r\n")

    s_initialize("delete")
    s_string("f0456", max_len=4)
    s_static("DELETE")
    s_delim(" ")
    s_static("wit_yu@163.com")
    s_static("\r\n")

    s_initialize("rename")
    s_string("p-92", max_len=4)
    s_static("RENAME")
    s_delim(" ")
    s_static("wit_yu@163.com")
    s_delim(" ")
    s_static("wie@163.com")
    s_static("\r\n")

    s_initialize("subscribe")
    s_string("o091", max_len=4)
    s_static("SUBSCRIBE")
    s_delim(" ")
    s_static("wit_yu@126.com")
    s_static("\r\n")

    s_initialize("unsubscribe")
    s_string("q001", max_len=4)
    s_static("UNSUBSCRIBE")
    s_delim(" ")
    s_static("wit_yu@126.com")
    s_static("\r\n")

    s_initialize("list")
    s_string("w001", max_len=4)
    s_static("LIST")
    s_delim(" ")
    s_static('"" *')
    s_static("\r\n")

    s_initialize("lsub")
    s_string("e001", max_len=4)
    s_static("LSUB")
    s_delim(" ")
    s_static(' ""*')
    s_static("\r\n")

    s_initialize("status")
    s_string("r001", max_len=4)
    s_static("STATUS")
    s_static("\r\n")

    s_initialize("append")
    s_string("t001", max_len=4)
    s_static("APPEND")
    s_delim(" ")
    s_static("<folder><attributes><date/time><size><mail data>")
    s_static("\r\n")

    # Selected#

    s_initialize("check")
    s_string("y--0", max_len=4)
    s_static("CHECK")
    s_string("\r\n")

    s_initialize("close")
    s_string("u=x1", max_len=4)
    s_static("CLOSE")
    s_static("\r\n")

    s_initialize("expunge")
    s_string("o000", max_len=4)
    s_static("EXPUNGE")
    s_static("\r\n")

    s_initialize("search")
    s_string("s==0", max_len=4)
    s_static("SEARCH")
    s_delim(" ")
    s_string("canshu")
    s_static("\r\n")

    s_initialize("store")
    s_string("d001", max_len=4)
    s_static("STORE")
    s_delim(" ")
    s_static("\r\n")

    s_initialize("copy")
    s_string("f001", max_len=4)
    s_static("CPOY")
    s_delim(" ")
    s_string("xulieji youxiangming")
    s_static("\r\n")

    s_initialize("uid")
    s_string("g001", max_len=4)
    s_static("UID")
    s_string("imap command")
    s_static("\r\n")

    s_initialize("fetch")
    s_string("h001", max_len=4)
    s_static("FETCH")
    s_string("ss ")
    s_static("\r\n")

    anys = ["capability", "noop", "logout"]
    unauth = ["starttls", "authenticate", "login"]
    auth = ["select", "examine", "create", "delete", "rename", "subscribe", "unsubscribe", "list", "lsub", "status",
            "append"]
    selected = ["check", "close", "expunge", "search", "store", "copy", "uid"]

    for cmd in anys:
        session.connect(s_get(cmd))
    for cmd in unauth:
        session.connect(s_get("capability"))
        session.connect(s_get("capability"), s_get("login"))
        session.connect(s_get(cmd))
    for cmd in auth:
        session.connect(s_get("capability"))
        session.connect(s_get("capability"), s_get("login"))
        session.connect(s_get("login"), s_get("list"))
        session.connect(s_get(cmd))
    for cmd in selected:
        session.connect(s_get("capability"))
        session.connect(s_get("capability"), s_get("login"))
        session.connect(s_get("login"), s_get("select"))
        session.connect(s_get(cmd))

    session.fuzz()





if __name__=="__main__":
    start_cmds = []
    proc_name = ""
    target_ip = "127.0.0.1"
    pport = 143
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)