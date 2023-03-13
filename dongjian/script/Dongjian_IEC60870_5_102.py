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
		},
        "Serial_Port": {
            "ness": 1,
            "default": "/dev/ttyS1"
        },
        "Baudrate": {
            "ness": 1,
            "default": 115200
        }
	},
	"proto": "iec60870-5-102"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        kwargs["Serial_Port"]
        kwargs["Baudrate"]

    except KeyError as e:
        print("lack of essensial parameter")
        return 0

    sess = Session(
        target=Target(
            connection=SerialConnection(port=kwargs["Serial_Port"],
                                        baudrate=kwargs["Baudrate"],
                                        timeout=5,
                                        message_separator_time=0.3)
        ),
        **kwargs
    )

    s_initialize("SingleByte")
    s_byte(name="sbyte", value=0xe5)

    s_initialize("FixedFrame")
    s_byte(name="start", value=0x10, fuzzable=False)
    s_block(name="link_control_field")
    s_bit_field(name="res", width=1, value=0)
    s_bit_field(name="prm", width=1, value=0)
    s_bit_field(name="fcb_acd", width=1, value=0)
    s_bit_field(name="fcv_dfc", width=1, value=0)
    s_bit_field(name="control_code", width=4, value=0)
    s_bytes(name="link_address", value=b"\x00\x00")
    s_block_end()
    s_checksum(name="check_sum", block_name="link_control_field", algorithm="mod256", length=1)
    s_byte(name="end", value=0x16, fuzzable=False)

    s_initialize("NonFixedFrame")
    s_byte(name="start1", value=0x68, fuzzable=False)
    s_size(name="len1", block_name="link_control_field", length=1)
    s_size(name="len2", block_name="link_control_field", length=1)
    s_byte(name="start2", value=0x68, fuzzable=False)
    s_block(name="link_control_field")
    s_bit_field(name="res", width=1, value=0)
    s_bit_field(name="prm", width=1, value=0)
    s_bit_field(name="fcb_acd", width=1, value=0)
    s_bit_field(name="fcv_dfc", width=1, value=0)
    s_bit_field(name="control_code", width=4, value=0)
    s_bytes(name="link_address", value=b"\x00\x00")
    if s_block_start(name="ASDU"):
        s_byte(name="type", value=0x00)
        s_byte(name="word", value=0x00)
        s_byte(name="reason", value=0x00)
        s_bytes(name="terminal_address", size=2, value=b"\x00\x00")
        s_byte(name="record_address", value=0x00)
        if s_block_start(name="inf_obj"):
            s_byte(name="ele_addr", value=0x00)
            s_random(name="container", value="00000", max_length=10000, min_length=2, num_mutations=25000)
            s_bytes(name="time", value=b"\x00\x00\x00\x00\x00\x00\x00", size=7)
        s_block_end()
        s_repeat(block_name="inf_obj", max_reps=2000, min_reps=5, step=1, name="info_obj")
    s_block_end()
    s_block_end()
    s_checksum(name="check_sum", block_name="link_control_field", algorithm="mod256", length=1)
    s_byte(name="end", value=0x16, fuzzable=False)

    # sess.connect(s_get("SingleByte"))
    # sess.connect(s_get("SingleByte"), s_get("FixedFrame"))
    # sess.connect(s_get("FixedFrame"), s_get("NonFixedFrame"))

    # sess.connect(s_get("SingleByte"))
    # sess.connect(s_get("FixedFrame"))
    sess.connect(s_get("NonFixedFrame"))
    sess.fuzz()

if __name__ == "__main__":
    target_ip = "10.38.4.112"
    start_cmds = []
    proc_name = ""
    pport = 0
    dport=26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, Serial_Port='/dev/ttyS1', Baudrate=115200)

