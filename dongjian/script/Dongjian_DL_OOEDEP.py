from DongJian import *
import datetime

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

def tohex(num, leng):
    tex = str(hex(num)).split('x')[-1]
    if len(tex) < leng:
        tex = '0'*(leng-len(tex))+tex
    return tex

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):


    session = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
            #procmon=pedrpc.Client('127.0.0.1', dport),
            # procmon_options={"start_commands": start_cmds, "proc_name": proc_name},
        ),
        **kwargs
    )

    s_initialize('logon')
    s_static('\x68')        #起始符
    if s_block('head'):
        s_static('\x1e\x00')    #长度
        s_static('\x81')        #控制
        s_random('00', max_length=7, min_length=7)  #SA
        s_static('\x00')           #CA
    s_block_end('head')
    s_checksum(block_name='head', algorithm='crc32', length=2)
    if s_block('frame', group='beat'):
        s_group(name='beat', values=['\x01\x00\x00', '\x01\x01\x01'])
        s_static('\x00\xb4')
        now = datetime.datetime.now()
        s_binary(tohex(now.year, 4))
        s_binary(tohex(now.month, 2))
        s_binary(tohex(now.day, 2))
        s_static('\x04')
        s_binary(tohex(now.hour, 2))
        s_binary(tohex(now.minute, 2))
        s_binary(tohex(now.second, 2))
        s_binary(tohex(int(str(now.microsecond)[0:4]), 4))
    s_block_end('frame')
    s_checksum(block_name='frame', algorithm='crc32', length=2)
    s_static('\x16')

    s_initialize('app')
    s_static('\x68')        #起始符
    if s_block('body'):
        if s_block('head'):
            s_size('body', length=2)    #长度
            s_static('\x81')        #控制
            s_random('00', max_length=7, min_length=7)  #SA
            s_static('\x00')           #CA
        s_block_end('head')
        s_checksum(block_name='head', algorithm='crc32', length=2)
        if s_block('frame'):
            s_random('00', min_length=4, max_length=512)
        s_block_end('frame')
        s_checksum(block_name='frame', algorithm='crc32', length=2)
    s_block_end('body')
    s_static('\x16')

    session.connect(s_get("logon"))
    session.connect(s_get("logon"), s_get("app"))

    session.fuzz()


if __name__ == "__main__":
    target_ip = "127.0.0.1"
    pport = 2404
    dport = 26002
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
