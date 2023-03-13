from DongJian import *
param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 666
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
	"proto": "MCWDT"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    session = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="udp"),
        ),
        **kwargs
    )

    s_initialize('selects')
    s_static('This is a test! ')
    s_random(' ', min_length=1, max_length=100)
    s_static('This is ended!!')

    session.connect(s_get("selects"))

    session.fuzz()


if __name__=="__main__":
    target_ip = "172.16.145.25"
    pport = 666
    dport = 26002
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
