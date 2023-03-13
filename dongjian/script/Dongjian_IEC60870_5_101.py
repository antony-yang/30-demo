import struct

import six

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
	"proto": "iec60870-5-101"
}

def sumcheck(cp):
    sum = 0
    for c in cp:
        sum += int(c)
    return hex(sum % 256)


def fuzz(start_cmds, proc_name, target_ip, pport, dport, taskname, *args, **kwargs):

    session = Session(
        target=Target( 
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
            #procmon=pedrpc.Client('127.0.0.1', dport),
            # procmon_options={"start_commands": start_cmds, "proc_name": proc_name},
        ),
        **kwargs
    )

    s_initialize('guding')
    s_static('\x10')
    with s_block('chain') as chain:
        s_random('\x00', max_length=1, min_length=1)
        s_group(name='address', values=[six.int2byte(i+1) for i in range(255)])
    s_checksum('chain', algorithm=sumcheck, length=1, fuzzable=False)
    s_static('\x16')

    s_initialize('kebian')
    s_static('\x68')
    s_size('chain', length=1)
    s_size('chain', length=1)
    s_static('\x68')
    with s_block('chain') as chain:
        s_random(name='control', value='\x00', max_length=1, min_length=1)
        s_group(name='address', values=[six.int2byte(i + 1) for i in range(255)])
        s_random(name="asdu", value='\x01\x07\x01\x00\x00\x14', max_length=249, min_length=6)
    s_checksum('chain', algorithm=sumcheck, length=1, fuzzable=False)
    s_static('\x16')

    session.connect(s_get("guding"))
    session.connect(s_get("guding"), s_get("kebian"))

    session.fuzz()


if __name__ == "__main__":
    target_ip = "10.38.4.112"
    pport = 2404
    dport = 26002
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
