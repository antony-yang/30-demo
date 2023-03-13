
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
			"default": ["C://Wireshark//Wireshark.exe"]
		}
	},
	"proto": "DNP"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):


    if start_cmds:
        sess = Session(
            target=Target(
                connection=SocketConnection(target_ip, pport, proto="tcp"),
                procmon=pedrpc.Client(target_ip, dport),
                procmon_options={"start_commands": [start_cmds]},
            ),
            **kwargs
        )
    else:
        sess = Session(
            target=Target(
                connection=SocketConnection(target_ip, pport, proto="tcp"),
            ),
            **kwargs
        )

    s_initialize("DNP3")
    if s_block_start("dnp header"):
        s_static("\x05\x64", name="start")
        s_size(block_name="data", length=1, endian=">", math=lambda x: 5+x-math.ceil(x/18.0)*2)
        # s_static("\05", name="length")
        s_byte(0x44, name="control", fuzzable=True)
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
                s_random(value="\x00" * 16, min_length=16, max_length=16, num_mutations=1000, name="a slice data")
            s_block_end("user data")
            s_checksum(block_name="user data", fuzzable=False, length=2, endian="<", algorithm="crc-dnp")
        s_block_end("user data block")
        # s_repeat(block_name="user data block", min_reps=3, max_reps=14, fuzzable=False)

        if s_block_start("last user data"):
            s_random(value="\x00", min_length=1, max_length=16, name="last data")
        s_block_end("last user data")
        s_checksum(block_name="last user data", fuzzable=False, length=2, endian="<", algorithm="crc-dnp")
    s_block_end("data")

    sess.connect(s_get("DNP3"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "172.16.145.25"
    start_cmds = ["C://Program Files//Wireshark//Wireshark.exe"]
    proc_name = ""
    pport = 20000
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
