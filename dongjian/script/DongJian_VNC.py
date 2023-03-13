from DongJian import *
from pyDes import des, ECB


param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 5901
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
		},
        "password": {
            "ness": 1,
            "default": "mininet"
        }
	},
	"proto": "vnc"
}

security_type = {
    "invalid": 0,
    "none": 1,
    "vnc": 2,
    "ra2": 5,
    "ra2ne": 6,
    "tight": 16,
    "ultra": 17,
    "tls": 18,
    "vencrypt": 19
}

KWA = {
    "password": ""
}

def callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    if KWA["password"] != "":
        password = bytes.fromhex(''.join([hex(int(format(ord(p), '08b')[::-1], 2)).replace('0x', '') for p in KWA['password']]))
        if len(password) < 8:
            password = password + b'\x00'*(8-len(password))
        elif len(password) > 8:
            password = password[0:8]
        des_obj = des(password, mode=ECB, IV="\x00\x00\x00\x00\x00\x00\x00\x00")
        node: Request
        block: Block = node.names["challenge"]
        block.stack[0]._value = des_obj.encrypt(session.last_recv)

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    #############################
    try:
        password = kwargs['password']
        KWA["password"] = password
    except Exception as e:
        password = None
    #############################

    session = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
        ),
        **kwargs
    )

    s_initialize('init')
    if s_block('init'):
        s_random('', min_length=10, max_length=10)
    s_block_end('init')

    s_initialize('version')
    if s_block('ver'):
        s_static('RFB 003.008\n')
    s_block_end('ver')

    if password is None:
        s_initialize('security')
        if s_block('type'):
            s_static('\x01')
        s_block_end('type')
        s_initialize('challenge')
        if s_block('cha'):
            s_random('asd', min_length=10, max_length=100)
        s_block_end('cha')
    else:
        s_initialize('security')
        if s_block('type'):
            s_static('\x02')
        s_block_end('type')
        s_initialize('challenge')
        if s_block('challenge'):
            s_static('\x00\x00\x00\x02')
        s_block_end('challenge')

    s_initialize("share")
    if s_block('flag'):
        s_static('\x01')
    s_block_end('flag')

    s_initialize("test")
    if s_block('init'):
        s_random('asd', min_length=13, max_length=16)
    s_block_end('init')

    session.connect(session.root, s_get("init"))
    session.connect(s_get("init"), s_get("version"))
    session.connect(s_get("version"), s_get("security"))
    session.connect(s_get("security"), s_get("challenge"), callback=callback)
    session.connect(s_get("challenge"), s_get("share"))
    session.connect(s_get("share"), s_get("test"))

    session.fuzz()


if __name__ == "__main__":
    target_ip = "10.1.4.130"
    pport = 5901
    dport = 26002
    start_cmds = []
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, password="mininet")
