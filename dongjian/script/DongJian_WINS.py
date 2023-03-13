from DongJian import *
import socket
socket.setdefaulttimeout(8)

param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 42
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
	"proto": "WINS"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(target_ip, pport, proto="tcp"),
        ),
        **kwargs
    )

    s_initialize('WINS_Association_Start_Request_Message')
    with s_block('length'):
        s_size(block_name="content", length=4, name='netbios_length', fuzzable=False, endian=">")
    with s_block('content'):
        s_dword(0x80047800, name="Reserved",fuzzable=False)
        s_dword(0x00, name="Destination_Association_Handle", fuzzable=False)
        s_dword(0x00, name="Message_Type ", fuzzable=False)

        s_dword(0x05371e90, name="Sender_Association_Handle")
        s_word(0x02, name="NBNS_Major_Version")
        s_word(0x05, name="NBNS_Minor_PVersion")
        s_bit_field(value=0x00, width=168, name="signature")


    s_initialize('WINS_Association_Start_Response_Message')
    with s_block('length'):
        s_size(block_name="content", length=4, name='netbios_length', fuzzable=False, endian=">")
    with s_block('content'):
        s_dword(0x78017805, name="Reserved",fuzzable=False)
        s_dword(0x05371e90, name="Destination_Association_Handle", fuzzable=False)
        s_dword(0x00000001, name="Message_Type ", fuzzable=False,endian=BIG_ENDIAN)

        s_dword(0x05371e90, name="Sender_Association_Handle", fuzzable=False)
        s_word(0x02, name="NBNS_Major_Version")
        s_word(0x05, name="NBNS_Minor_PVersion")
        s_bit_field(value=0x00, width=168, name="signature",fuzzable=False)


    s_initialize('WINS_Association_Stop_Request_Message')
    with s_block('length'):
        s_size(block_name="content", length=4, name='netbios_length', fuzzable=False, endian=">")
    with s_block('content'):
        s_dword(0x00, name="Reserved")
        s_dword(0x00, name="Destination_Association_Handle", fuzzable=False)
        s_dword(0x02, name="Message_Type ", fuzzable=False, endian=BIG_ENDIAN)

        s_dword(0x00, name="Association_Stop_Reason")
        s_bit_field(value=0x00, width=24*8, name="Reserved ")


    s_initialize('WINS_Name_Records_Request_Message')
    with s_block('length'):
        s_size(block_name="content", length=4, name='netbios_length', fuzzable=False, endian=">")
    with s_block('content'):
        s_bit_field(value=0x00, width=3*8, name="Reserved1")
        s_byte(0x02, name="RplOpCode", fuzzable=False)
        s_dword(0x00, name="Owner_of_Owners")
        s_dword(0x00, name="Max_Version_Number_Hi")
        s_dword(0x00, name="Max_Version_Number_Lo")
        s_dword(0x00, name="Mini_Version_Number_Hi")
        s_dword(0x00, name="Mini_Version_Number_Lo")
        s_dword(0x00, name="Reserved2")

    s_initialize('WINS_Name_Records_Response_Message')
    with s_block('length'):
        s_size(block_name="content", length=4, name='netbios_length', fuzzable=False, endian=">")
    with s_block('content'):
        s_bit_field(value=0x00, width=3*8, name="Reserved1")
        s_byte(0x03, name="RplOpCode",fuzzable=False)
        s_dword(0x00, name="Number_of_Name_Records ")
        s_random("\x00\x00\x00\x00", min_length=4, max_length=100,
                 name="Owner_Record", step=4)

    s_initialize('WINS_Owner-Version_Map_Request_Message')
    with s_block('length'):
        s_size(block_name="content", length=4, name='netbios_length', fuzzable=False, endian=">")
    with s_block('content'):
        s_dword(0x00, name="Reserved")
        s_dword(0x00, name="Destination_Association_Handle", fuzzable=False)
        s_dword(0x03, name="Message_Type ", fuzzable=False, endian=BIG_ENDIAN)

        s_bit_field(value=0x00, width=3*8, name="Reserved ")
        s_byte(0x00,name="RplOpCode")

    s_initialize('WINS_Owner-Version_Map_Response_Message')
    with s_block('length'):
        s_size(block_name="content", length=4, name='netbios_length', fuzzable=False, endian=">")
    with s_block('content'):
        s_dword(0x00, name="Reserved")
        s_dword(0x00, name="Destination_Association_Handle", fuzzable=False)
        s_dword(0x03, name="Message_Type ", fuzzable=False,endian=BIG_ENDIAN)

        s_bit_field(value=0x00, width=3*8, name="Reserved1")
        s_byte(0x01, name="RplOpCode")
        s_dword(0x00, name="Number_of_Owners")
        s_random("\x00\x00\x00\x00", min_length=4, max_length=100,
                 name="Owner_Record")
        s_dword(0x00, name="Reserved2")

    s_initialize('WINS_Update_Notification_Message')
    with s_block('length'):
        s_size(block_name="content", length=4, name='netbios_length', fuzzable=False, endian=">")
    with s_block('content'):
        s_bit_field(value=0x00, width=3*8, name="Reserved1")
        s_byte(0x01, name="RplOpCode")
        s_dword(0x00, name="Number_of_Owners")
        s_random("\x00\x00\x00\x00", min_length=4, max_length=100,
                 name="Owner_Record")
        s_dword(0x00, name="Initiator_IPv4_Address")

    sess.connect(s_get("WINS_Update_Notification_Message"))

    sess.connect(s_get("WINS_Owner-Version_Map_Response_Message"))

    sess.connect(s_get("WINS_Owner-Version_Map_Request_Message"))

    sess.connect(s_get("WINS_Name_Records_Response_Message"))

    sess.connect(s_get("WINS_Name_Records_Request_Message"))

    sess.connect(s_get("WINS_Association_Stop_Request_Message"))

    sess.connect(s_get("WINS_Association_Start_Response_Message"))

    sess.connect(s_get("WINS_Association_Start_Request_Message"))

    sess.fuzz()

if __name__ == "__main__":
    target_ip = "192.168.72.1"
    start_cmds = []
    proc_name = ""
    pport = 42
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)