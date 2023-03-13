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
	"proto": "MCWDT"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    session = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
            #procmon=pedrpc.Client('127.0.0.1', dport),
            # procmon_options={"start_commands": start_cmds, "proc_name": proc_name},
        ),
        **kwargs
    )

    s_initialize('con')
    s_static('\x68')                                             #起始符
    s_size('frame', length=2, math=lambda x: (x << 2)+2)
    s_static('\x68')
    if s_block('frame'):
        s_random('\xf8', max_length=1, min_length=1)             #控制
        s_random('\x11\x00', max_length=2, min_length=2)         #行政编码
        s_random('\xff\xff', max_length=2, min_length=2)         #CA
        s_random('\x00', max_length=1, min_length=1)             #SA
        s_random('\x00', max_length=16377, min_length=1)
    s_block_end('frame')
    s_checksum(block_name='frame', algorithm='crc32', length=2)
    s_static('\x16')                                             #结束符

    session.connect(s_get("con"))

    session.fuzz()


if __name__ == "__main__":
    target_ip = "127.0.0.1"
    pport = 2404
    dport = 26002
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
