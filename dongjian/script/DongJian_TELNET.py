from DongJian import *
param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 23
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
	"proto": "TELNET"
}
def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    session = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
            # procmon=pedrpc.Client(target_ip, dport),
            # procmon_options={"start_commands": start_cmds, "proc_name": proc_name},
        ),
        **kwargs
    )
    #
    s_initialize('selects')
    s_static('\xff')
    s_group(name='selects', values=['\xfb', '\xfc', '\xfd', '\xfe'])
    s_group(name='options', values=['\x01', '\x03', '\x05', '\x06', '\x18',
                                    '\x1f', '\x20', '\x21', '\x22', '\x24'])
    s_string('00', max_len=1490)

    s_initialize('subselects')
    s_static('\xff')
    s_static(name='subselects', value='\xf0')
    s_group(name='options', values=['\x01', '\x03', '\x05', '\x06', '\x18',
                                   '\x1f', '\x20', '\x21', '\x22', '\x24'])
    s_string('00', max_len=1490)

    s_initialize("actions")
    s_static('\xff')
    s_group(name='commands', values=['\xec', '\xed', '\xee', '\xef', '\xf0'
                                     '\xf1', '\xf2', '\xf3', '\xf4', '\xf5',
                                     '\xf6', '\xf7', '\xf8', '\xf9',
                                     ])

    session.connect(s_get("selects"))
    session.connect(s_get("subselects"))
    session.connect(s_get("actions"))

    session.fuzz()


if __name__=="__main__":
    target_ip = "172.16.145.25"
    pport = 23
    dport = 26002
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
