from DongJian import *
param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 8080
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
	"proto": "iec61970-xml"
}
def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    session = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
        ),
        **kwargs
    )

    s_initialize('xml')
    s_static('\x3c\x72\x64\x66\x73\x3a\x43\x6c\x61\x73\x73\x20\x72\x64\x66\x3a\x61\x62\x6f\x75\x74\x3d\x22')
    s_random('\x00', max_length=24, min_length=0)
    s_static('\x22\x3e\x0a')
    s_static('\x3c\x72\x64\x66\x73\x3a\x6c\x61\x62\x65\x6c\x3e')
    s_random('\x00', max_length=24, min_length=0)
    s_static('\x3c\x2f\x72\x64\x66\x73\x3a\x6c\x61\x62\x65\x6c\x3e\x0a')
    s_static('\x3c\x63\x69\x6d\x73\x3a\x62\x65\x6c\x6f\x6e\x67\x73\x54\x6f\x43\x61\x74\x65\x67\x6f\x72\x79\x20\x72\x64\x66\x3a\x72\x65\x73\x6f\x75\x72\x63\x65\x3d\x22')
    s_random('\x00', max_length=24, min_length=0)
    s_static('\x22\x2f\x3e\x0a')
    s_static('\x3c\x2f\x72\x64\x66\x73\x3a\x43\x6c\x61\x73\x73\x3e\x0a')

    session.connect(s_get("xml"))

    session.fuzz()


if __name__ == "__main__":
    target_ip = "10.1.0.102"
    pport = 8080
    dport = 26002
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
