from DongJian import *
param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 2481
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
	"proto": "iec61968-giop"
}
def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    session = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
        ),
        **kwargs
    )

    s_initialize('giop')
    s_static('\x47\x49\x4f\x50\x01\x02\x00\x01\x00\x00\x00')
    if s_block('con'):
        s_size('con', length=1)
        s_random('00', max_length=200, min_length=20)
    s_block_end('con')
    s_random('00', max_length=1, min_length=1)
    session.connect(s_get("giop"))
    session.fuzz()


if __name__ == "__main__":
    target_ip = "10.1.0.102"
    pport = 2481
    dport = 26002
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
