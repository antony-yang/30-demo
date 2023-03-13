
from DongJian import *
import math

param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 20000
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
			"default": [""]
		}
	},
	"proto": "DNP"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(target_ip, pport, proto="tcp"),
        ),
        **kwargs
    )

    control_fun = ['\x00', '\x01', '\x03', '\x04', '\x09',
               '\x10', '\x11', '\x13', '\x14', '\x19',
               '\x20', '\x21', '\x23', '\x24', '\x29',
               '\x30', '\x31', '\x33', '\x34', '\x39',
               '\x40', '\x41', '\x43', '\x44', '\x49',
               '\x50', '\x51', '\x53', '\x54', '\x59',
               '\x60', '\x61', '\x63', '\x64', '\x69',
               '\x70', '\x71', '\x73', '\x74', '\x79',
               '\x80', '\x81', '\x83', '\x84', '\x89',
               '\x90', '\x91', '\x93', '\x94', '\x99',
               '\xa0', '\xa1', '\xa3', '\xa4', '\xa9',
               '\xb0', '\xb1', '\xb3', '\xb4', '\xb9',
               '\xc0', '\xc1', '\xc3', '\xc4', '\xc9',
               '\xd0', '\xd1', '\xd3', '\xd4', '\xd9',
               '\xe0', '\xe1', '\xe3', '\xe4', '\xe9',
               '\xf0', '\xf1', '\xf3', '\xf4', '\xf9']

    control_fun2 = ['\x00', '\x10',
               '\x20',
               '\x30',
               '\x40',
               '\x50',
               '\x60',
               '\x70',
               '\x80',
               '\x90',
               '\xa0',
               '\xb0',
               '\xc0',
               '\xd0',
               '\xe0',
               '\xf0']

    s_initialize("DNP3")
    if s_block_start("dnp header"):
        s_static("\x05\x64", name="start")
        s_size(block_name="data", length=1, endian=">", math=lambda x: 5+x-math.ceil(x/18.0)*2, fuzzable=False)
        s_group(name="control", values=control_fun2, default_value='\x44')
        s_string(value="\x04\x00", name="destination", max_len=2)
        s_string(value="\x03\x00", name="source", max_len=2)
        # s_static("\x04\x00", name="destination")
        # s_static("\x03\x00", name="source")
    s_block_end("dnp header")
    print(blocks.CURRENT.names["dnp header"])
    s_checksum("dnp header", fuzzable=False, length=2, endian="<", algorithm="crc-dnp")

    if s_block_start("data"):
        if s_block_start("user data block"):
            if s_block_start("user data"):
                # s_random(value="\x00" * 16, min_length=16, max_length=16, num_mutations=1000, name="a slice data")
                s_static('\x01'*16)
            s_block_end("user data")
            s_checksum(block_name="user data", fuzzable=False, length=2, endian="<", algorithm="crc-dnp")
        s_block_end("user data block")
        # s_repeat(block_name="user data block", min_reps=3, max_reps=14, fuzzable=False)
        #
        # if s_block_start("last user data"):
        #     # s_random(value="\x00", min_length=1, max_length=16, name="last data")
        #     s_static('\x01' * 16)
        # s_block_end("last user data")
        # s_checksum(block_name="last user data", fuzzable=False, length=2, endian="<", algorithm="crc-dnp")
    s_block_end("data")

    sess.connect(s_get("DNP3"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "172.16.145.25"
    start_cmds = []
    proc_name = ""
    pport = 20000
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
