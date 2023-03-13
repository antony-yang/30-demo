#!/usr/bin/env python


from DongJian import *
import socket
import base64

param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 22403
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
	"proto": "iec60870-5-103"
}

def calc_checksum(msg):
    remsg = []
    for index,v in enumerate(msg):
        if index == 2:
            v = (remsg[0] + remsg[1]) % 256
        remsg.append(v)
    return bytes(remsg)


def fix_variable_length_data(variable_length_data):
    checksum_index = len(variable_length_data) - 1
    length = len(variable_length_data) - 4
    high4 = (length & 0xFFFF) >> 8
    low8 = length & 0xFF
    remsg = []
    totolsum = 0
    for index,v in enumerate(variable_length_data):
        if index == 0:
            v = low8
        elif index == 1:
            v = high4
        elif index == checksum_index:
            v = totolsum % 256
        elif index == 2:
            v = v
        else:
            totolsum +=v
        remsg.append(v)
    return bytes(remsg)


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    socket.setdefaulttimeout(8)
    session = Session(
        target=Target(
            connection=SocketConnection(target_ip, pport, proto="tcp"),
        ),
        **kwargs
    )


    """ IEC-60870-5-103 data model. """

    #定长数据包
    s_initialize("fixed_length_data")
    s_byte(0x10,name="msgstartbyte",fuzzable=False)
    s_block_start("msg", None, calc_checksum)
    s_byte(0x00,name="control",fuzzable=True,full_range=True)
    s_byte(0xFF, name="address", fuzzable=False)
    s_byte(0x00, name="checksum")
    s_block_end()
    s_byte(0x16, name="msgendbyte", fuzzable=False)


    #可变长数据包
    s_initialize("variable_length_data")
    s_byte(0x68, name="msgstartbyte", fuzzable=False)
    s_block_start("variable_length_data", None, fix_variable_length_data)
    s_byte(0x00, name="length(low8)", fuzzable=False)
    s_byte(0x00, name="length(high4)", fuzzable=False)
    s_byte(0x68, name="msgstartbyte_repeat", fuzzable=False)
    s_byte(0x00, name="control", fuzzable=True, full_range=True)
    s_byte(0xFF, name="address", fuzzable=False)
    #ASDU
    s_string("")
    #ASDU end
    s_byte(0x00, name="checksum")
    s_block_end()
    s_byte(0x16, name="msgendbyte", fuzzable=False)


    session.connect(s_get("variable_length_data"))
    session.fuzz()


if __name__ == "__main__":
    target_ip = "10.38.4.112"
    start_cmds = [""]
    proc_name = ""
    pport = 22403
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)