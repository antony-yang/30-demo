from DongJian import *
param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 102
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
	"proto": "iec61850-mms"
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

    s_initialize('initiate')
    if s_block('tpkt'):
        s_static('\x03\x00\x00')
        s_size('tpkt', length=1)
        if s_block('cotp'):
            s_static('\x02')
            s_static('\xf0')
            s_static('\x80')
            s_block_end('cotp')
            s_binary('010001006130302e020103a029')
            if s_block('init'):
                s_static('\xa8')
                s_size('init', length=1)
                s_random('00', max_length=38, min_length=28)
            s_block_end('init')
    s_block_end('tpkt')


    s_initialize('confirmed')
    if s_block('tpkt'):
        s_static('\x03\x00\x00')
        s_size('tpkt', length=1)
        if s_block('cotp'):
            s_static('\x02')
            s_static('\xf0')
            s_static('\x80')
            s_block_end('cotp')
            s_binary('010001006130302e020103a029')
            # s_binary('010001006130302e020103')
            if s_block('read'):
                s_static('\xa0')
                s_size('read', length=1)
                s_static('\x02\x02')
                s_random('\x00\x00', min_length=2, max_length=2)
                s_static('\xa4\x21')
                s_static('\x80\x01\x01')
                s_random('00', max_length=30, min_length=30)
            s_block_end('read')
    s_block_end('tpkt')

    # session.connect(s_get("initiate"))
    session.connect(s_get("confirmed"))

    session.fuzz()


if __name__=="__main__":
    target_ip = "192.168.1.191"
    pport = 102
    dport = 26002
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
