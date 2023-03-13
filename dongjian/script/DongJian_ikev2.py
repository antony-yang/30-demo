from DongJian import *
import uuid
import socket
import fcntl
import struct
import random
socket.setdefaulttimeout(8)

param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 500
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
	"proto": "ikev2"
}


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):


    sess = Session(
        target=Target(
            connection=SocketConnection(target_ip, pport, proto="udp"),
        ),
        **kwargs
    )

    s_initialize('ikev2_sa_init')
    with s_block('ike_header'):   # ISAKMP
        s_random(value='\x5c\x32\x30\x47\x28\xfa\xb7\xd5', min_length=8, max_length=8, name='i_spi')
        s_static(value='\x00'*8, name='r_spi')
        s_static(value='\x01', name='next_payload')
        s_static(value='\x20', name='version')
        s_static(value='\x22', name='exchange_type')
        s_static(value='\x00', name='flags')
        s_static(value='\x00'*4, name='message_id')
        s_size(block_name='payloads', length=4, endian='>', name='length')
    with s_block('payloads'):
        with s_block('payload_sa'):
            s_static(value='\x00', name='sa_next_payload')
            s_static(value='\x00', name='sa_reserved')
            s_static(value='\x00\x38', name='sa_length')
            s_static(value='\x00\x00\x00\x01', name='domain')
            s_static(value='\x00\x00\x00\x01', name='sa_situation')
            with s_block('payload_proposal'):
                s_static(value='\x00', name='p_next_payload')
                s_static(value='\x00', name='p_reserved')
                s_static(value='\x00\x2c', name='p_length')
                s_static(value='\x00', name='p_number')
                s_static(value='\x01', name='p_id')
                s_static(value='\x00', name='spi_size')
                s_static(value='\x01', name='proposal_transforms')
                with s_block('payload_transform'):
                    s_static(value='\x00', name='t_next_payload')
                    s_static(value='\x00', name='t_reserved')
                    s_static(value='\x00\x24', name='t_length')
                    s_static(value='\x01', name='t_number')
                    s_static(value='\x01', name='t_id')
                    s_static(value='\x00\x00', name='t_reversed')
                    with s_block('ike_attribute_1'):
                        s_static(value='\x80\x01', name='1_type')
                        s_static(value='\x00\x07', name='1_value')
                    with s_block('ike_attribute_2'):
                        s_static(value='\x80\x0e', name='2_type')
                        s_static(value='\x00\x80', name='2_value')
                    with s_block('ike_attribute_3'):
                        s_static(value='\x80\x02', name='3_type')
                        s_static(value='\x00\x02', name='3_value')
                    with s_block('ike_attribute_4'):
                        s_static(value='\x80\x04', name='4_type')
                        s_static(value='\x00\x02', name='4_value')
                    with s_block('ike_attribute_5'):
                        s_static(value='\x80\x03', name='5_type')
                        s_static(value='\x00\x01', name='5_value')
                    with s_block('ike_attribute_6'):
                        s_static(value='\x80\x0b', name='6_type')
                        s_static(value='\x00\x01', name='6_value')
                    with s_block('ike_attribute_7'):
                        s_static(value='\x80\x0c', name='7_type')
                        s_static(value='\x0e\x10', name='7_value')




    s_initialize('ikev2_auth')
    with s_block('ike_header'):   # ISAKMP
        s_random(value='\x5c\x32\x30\x47\x28\xfa\xb7\xd5', min_length=8, max_length=8, name='i_spi_auth')
        s_static(value='\x00'*8, name='r_spi_auth')
        s_static(value='\x01', name='next_payload_auth')
        s_static(value='\x20', name='version_auth')
        s_static(value='\x22', name='exchange_type_auth')
        s_static(value='\x00', name='flags_auth')
        s_static(value='\x00'*4, name='message_id_auth')
        s_size(block_name='payloads_auth', offset=28, length=4, endian='>', name='length')
    with s_block('payloads_auth'):
            s_static(value='\x00', name='next_payload')
            s_static(value='\x00', name='reserved')
            s_size(block_name='payloads_auth',  length=4, endian='>', name='payloads_length')
            s_static(value='\x00\x02', name='fragment_number')
            s_static(value='\x00\x02', name='total_fragments')
            s_random("", min_length=0x10, max_length=0x30)


    #sess.connect(s_get("ikev2_sa_init"))
    sess.connect(s_get("ikev2_auth"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "192.168.159.1"
    start_cmds = []
    proc_name = ""
    pport = 500
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
