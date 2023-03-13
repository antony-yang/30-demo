from DongJian import *
import DongJian.instrumentation
import os
import time

param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 47808
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
			"default": []
		}
	},
	"proto": "BAC_net"
}

def target_alive(target_ip):
    response = os.system("ping -c 1 " + target_ip)
    if response == 0:
        return True
    else:
        return False


def reset_target():
    print("Stopping target\n")

    time.sleep(10)
    return True


def fuzz(start_cmds, proc_name, target_ip, pport, dport,  *args, **kwargs):

    session = Session(**kwargs)
    target = Target(connection=SocketConnection(target_ip, pport, proto='udp'))
    # target.procmon = DongJian.instrumentation.External(pre=None, post=target_alive, start=reset_target, stop=None)
    session.add_target(target)

    # start bacnet request packet
    s_initialize("bacnet_request_packet")
    if s_block_start("bacnet_virtual_link_control"):
        s_byte(0x81, name='type')
        s_byte(0x0a, name='function')
        s_word(0x1100, name='bvlc-length')
    s_block_end()
    if s_block_start("bacnet_npdu"):
        s_byte(0x01, name='version')
        s_byte(0x04, name='control')
    s_block_end()
    if s_block_start("bacnet_apdu"):
        s_byte(0x00, name='apdu_type')
        s_byte(0x05, name='max_response_segments')
        s_byte(0x01, name='invoke_id')
        s_byte(0x0c, name='service_choice')
        s_byte(0x0c, name='context_tag1')
        s_dword(0xffff3f02, name='object_type')
        s_byte(0x19, name='context_tag')
        s_byte(0x79, name='property_identifier')
    s_block_end()
    # end bacnet request packet

    session.connect(s_get("bacnet_request_packet"))
    session.fuzz()


if __name__ == "__main__":
    target_ip = "10.38.4.16"
    start_cmds = []
    proc_name = ""
    pport = 47808
    dport = 26002
    # target_alive(target_ip)
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
