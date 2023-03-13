from DongJian import *

param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 445
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
	"proto": "SMBv1"
}
def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    session = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
        ),
        **kwargs
    )

    s_initialize('init')
    if s_block('session'):
        s_static('\x00')
        s_size(block_name="session", offset=-4, length=3, fuzzable=False, endian=BIG_ENDIAN)
        if s_block('header'):
            s_static('\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x43\xc8')
            s_static('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            s_static('\x01\x00')
        s_block_end('header')
        if s_block('negotiate'):
            s_static('\x00')
            s_size(block_name="negotiate", offset=-3, length=2, fuzzable=False, endian=BIG_ENDIAN)
            s_random('PC NET WORK PROGRAM', min_length=0, max_length=184)
        s_block_end('negotiate')
    s_block_end('session')

    s_initialize('setup')
    if s_block('session'):
        s_static('\x00')
        s_size(block_name="session", offset=-4, length=3, fuzzable=False, endian=BIG_ENDIAN)
        if s_block('header'):
            s_static('\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x08\x43\xc8')
            s_static('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            s_static('\x01\x00')
        s_block_end('header')
        if s_block('andx'):
            s_size(block_name="andx", inclusive=True, length=1, fuzzable=False, endian=BIG_ENDIAN, math=lambda x: x//15)
            s_random('\xff\x00\x00\x00\x00\x00', min_length=0, max_length=184)
        s_block_end('andx')
    s_block_end('session')

    s_initialize('tree')
    if s_block('session'):
        s_static('\x00')
        s_size(block_name="session", offset=-4, length=3, fuzzable=False, endian=BIG_ENDIAN)
        if s_block('header'):
            s_static('\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x08\x03\xc8')
            s_static('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            s_static('\x01\x00')
        s_block_end('header')
        if s_block('andx'):
            s_size(block_name="andx", inclusive=True, length=1, fuzzable=False, endian=BIG_ENDIAN,
                   math=lambda x: x // 15)
            s_random('\xff\x00\x00\x00\x00\x00\x35\00', min_length=0, max_length=184)
        s_block_end('andx')
    s_block_end('session')

    s_initialize('query')
    if s_block('session'):
        s_static('\x00')
        s_size(block_name="session", offset=-4, length=3, fuzzable=False, endian=BIG_ENDIAN)
        if s_block('header'):
            s_static('\xff\x53\x4d\x42\x80\x00\x00\x00\x00\x08\x03\xc8')
            s_static('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            s_static('\x01\x00')
        s_block_end('header')
        if s_block('info'):
            s_static('\x00')
            s_size(block_name="info", offset=-3, length=2, fuzzable=False, endian=BIG_ENDIAN)
            s_random('', min_length=0, max_length=184)
        s_block_end('info')
    s_block_end('session')

    s_initialize('trans')
    if s_block('session'):
        s_static('\x00')
        s_size(block_name="session", offset=-4, length=3, fuzzable=False, endian=BIG_ENDIAN)
        if s_block('header'):
            s_static('\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x08\x03\xc8')
            s_static('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            s_static('\x01\x00')
        s_block_end('header')
        if s_block('request'):
            s_size(block_name="request", offset=-8, inclusive=True, length=1, fuzzable=False, endian=BIG_ENDIAN, math=lambda x: x//2)
            s_random('', min_length=0, max_length=184)
        s_block_end('request')
    s_block_end('session')

    s_initialize('delete')
    if s_block('session'):
        s_static('\x00')
        s_size(block_name="session", offset=-4, length=3, fuzzable=False, endian=BIG_ENDIAN)
        if s_block('header'):
            s_static('\xff\x53\x4d\x42\x06\x00\x00\x00\x00\x08\x03\xc8')
            s_static('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            s_static('\x01\x00')
        s_block_end('header')
        if s_block('request'):
            s_static('\x00')
            s_size(block_name="request", offset=-3, length=2, fuzzable=False, endian=BIG_ENDIAN)
            s_random('', min_length=0, max_length=184)
        s_block_end('request')
    s_block_end('session')

    s_initialize('nt')
    if s_block('session'):
        s_static('\x00')
        s_size(block_name="session", offset=-4, length=3, fuzzable=False, endian=BIG_ENDIAN)
        if s_block('header'):
            s_static('\xff\x53\x4d\x42\xa2\x00\x00\x00\x00\x08\x03\xc8')
            s_static('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            s_static('\x01\x00')
        s_block_end('header')
        if s_block('request'):
            s_size(block_name="request", offset=-2, inclusive=True, length=1, fuzzable=False, endian=BIG_ENDIAN,
                   math=lambda x: x // 4)
            s_random('\xff\x00\x00\x00\x00', min_length=0, max_length=184)
        s_block_end('request')
    s_block_end('session')

    s_initialize('write')
    if s_block('session'):
        s_static('\x00')
        s_size(block_name="session", offset=-4, length=3, fuzzable=False, endian=BIG_ENDIAN)
        if s_block('header'):
            s_static('\xff\x53\x4d\x42\x2f\x00\x00\x00\x00\x08\x03\xc8')
            s_static('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            s_static('\x01\x00')
        s_block_end('header')
        if s_block('request'):
            s_size(block_name="request", offset=-10, inclusive=True, length=1, fuzzable=False, endian=BIG_ENDIAN,
                   math=lambda x: x // 2)
            s_random('\xff\x00\x00\x00\x00', min_length=0, max_length=184)
        s_block_end('request')
    s_block_end('session')

    s_initialize("random")
    if s_block('session'):
        s_static('\x00')
        s_size(block_name="session", offset=-4, length=3, fuzzable=False, endian=BIG_ENDIAN)
        if s_block('header'):
            s_static('\xff\x53\x4d\x42')
            s_random('\x22', min_length=1, max_length=1)
            s_static('\x00\x00\x00\x00')
            s_random('\x08\x03\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00', min_length=23, max_length=23)
        s_block_end('header')
        if s_block('request'):
            s_random('', min_length=0, max_length=184)
        s_block_end('request')
    s_block_end('session')

    s_initialize('disconnect')
    if s_block('session'):
        s_static('\x00')
        s_size(block_name="session", offset=-4, length=3, fuzzable=False, endian=BIG_ENDIAN)
        if s_block('header'):
            s_static('\xff\x53\x4d\x42\x71\x00\x00\x00\x00\x08\x03\xc8')
            s_static('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            s_static('\x01\x00')
        s_block_end('header')
        if s_block('request'):
            s_static('\x00')
            s_size(block_name="request", offset=-3, length=2, fuzzable=False, endian=BIG_ENDIAN)
            s_random('', min_length=0, max_length=184)
        s_block_end('request')
    s_block_end('session')

    session.connect(session.root, s_get("init"))
    session.connect(s_get("init"), s_get("setup"))
    session.connect(s_get("setup"), s_get("tree"))
    session.connect(s_get("tree"), s_get("query"))
    session.connect(s_get("query"), s_get("trans"))
    session.connect(s_get("trans"), s_get("delete"))
    session.connect(s_get("delete"), s_get("nt"))
    session.connect(s_get("nt"), s_get("write"))
    session.connect(s_get("write"), s_get("random"))
    session.connect(s_get("trans"), s_get("disconnect"))

    session.fuzz()


if __name__ == "__main__":
    target_ip = "192.168.72.1"
    pport = 445
    dport = 102
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
