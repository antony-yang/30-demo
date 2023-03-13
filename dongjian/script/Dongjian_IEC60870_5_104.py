from DongJian import *

param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 2404
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
	"proto": "iec60870-5-104"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    session = Session(
        target=Target( 
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
        ),
        **kwargs
    )

    s_initialize('i')
    s_static('\x68')
    if s_block('con'):
        s_static('\x0e')
        s_random('00', max_length=2, min_length=2)
        s_random('00', max_length=2, min_length=2)
    if s_block('asdu'):
        s_random('\x2d', max_length=1, min_length=1)
        s_group(name='as', values=['\x00', '\x01'])
        s_static('\x06')
        s_random('\x00\x01\x00\x00\x00\x00\x80', max_length=7, min_length=7)
    s_block_end('asdu')
    s_block_end('con')

    s_initialize('su')
    s_static('\x68')
    s_random('\x80', max_length=1, min_length=1)
    if s_block('con'):
        s_static('\x04')
        s_random('00', max_length=4, min_length=4)
    s_block_end('con')

    session.connect(s_get("i"))
    session.connect(s_get("su"))

    session.fuzz()


if __name__ == "__main__":
    target_ip = "10.38.4.112"
    pport = 2404
    dport = 2404
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
