import random
from DongJian import *

param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 139
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
	"proto": "SMBv2"
}

def SendAbortCmd(target, fuzz_data_logger, session, sock):
    target.send(b"\x01\x0a")
    pass

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
        ),
        **kwargs
    )

    s_initialize("SMB_cancel_response")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x0c\x00', name="command")  # cancel need set command to 0x0d
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x04\x00", name="StructureSize")
            s_word(value=0x00, name="Reserved")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize('smb_CHANGE_NOTIFY_request')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x000F, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_CHANGE_NOTIFY_request_body"):
            s_binary('0x200x00', name="structure_size")
            s_word(0x00, name="flags")
            s_dword(0x00, name="output_buffer_length")
            s_bit_field(value=0x00, width=128, name="file_id")
            s_dword(0x00, name="completion_filter")
            s_dword(0x00, name="reserved_2")
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('smb_CHANGE_NOTIFY_response')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x000F, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_CHANGE_NOTIFY_response_body"):
            s_binary('0x090x00', name="structure_size")
            s_word(0x81 - 0x3a, name="output_buffer_offset", fuzzable=False)
            output_buffer_length = random.randint(0, 101)
            s_dword(output_buffer_length, name="output_buffer_length", fuzzable=False)
            s_random("\x00" * output_buffer_length, min_length=output_buffer_length, max_length=output_buffer_length,
                     name="buffer")

        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize("SMB_close_request")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x06\x00', name="command")  # close need set command to 6
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x18\x00", name="StructureSize")
            s_word(value=0x01, name="Flags")
            s_dword(value=0x00, name="Reserved")
            s_bit_field(value=0x00, width=128, name="FileId")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_close_response")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x05\x00', name="command")  # close need set command to 6
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x3c\x00", name="StructureSize")
            s_word(value=0x01, name="Flags")
            s_dword(value=0x00, name="Reserved")
            s_qword(value=0x00, name="CreationTime")
            s_qword(value=0x00, name="LastAccessTime")
            s_qword(value=0x00, name="LastWriteTime")
            s_qword(value=0x00, name="ChangeTime")
            s_qword(value=0x00, name="AllocationSize")
            s_qword(value=0x00, name="EndofFile")
            s_dword(value=0x00, name="FileAttributes")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_create_request")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x05\x00', name="command")  # create need set command to 5
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x39\x00", name="StructureSize")
            s_byte(value=0x00, name="SecurityFlags")
            s_group("RequestedOplockLevel", ["\x00", "\x01", "\x08", "\x09", "\xff"])
            s_group("ImpersonationLevel",
                    ["\x00\x00\x00\x00", "\x01\x00\x00\x00", "\x02\x00\x00\x00", "\x03\x00\x00\x00"])
            s_qword(value=0x00, name="SmbCreateFlags")
            s_qword(value=0x00, name="Reserved")
            s_dword(value=0x00, name="DesiredAccess")
            s_dword(value=0x00, name="FileAttributes")
            s_group("ShareAccess", ["\x01\x00\x00\x00", "\x02\x00\x00\x00", "\x04\x00\x00\x00"])
            s_group("CreateDisposition",
                    ["\x00\x00\x00\x00", "\x01\x00\x00\x00", "\x02\x00\x00\x00", "\x03\x00\x00\x00", "\x04\x00\x00\x00",
                     "\x05\x00\x00\x00"])
            s_group("CreateOptions",
                    ["\x01\x00\x00\x00", "\x02\x00\x00\x00", "\x04\x00\x00\x00", "\x08\x00\x00\x00", "\x10\x00\x00\x00",
                     "\x20\x00\x00\x00", \
                     "\x40\x00\x00\x00", "\x00\x01\x00\x00", "\x00\x02\x00\x00", "\x00\x04\x00\x00", "\x00\x08\x00\x00",
                     "\x00\x10\x00\x00", \
                     "\x00\x20\x00\x00", "\x00\x40\x00\x00", "\x00\x80\x00\x00", "\x00\x00\x01\x00", "\x00\x00\x02\x00",
                     "\x00\x00\x10\x00", \
                     "\x00\x00\x20\x00", "\x00\x00\x40\x00", "\x00\x00\x80\x00"])
            s_word(value=0x00, name="NameOffset")
            s_word(value=0x00, name="NameLength")
            s_dword(value=0x00, name="CreateContextsOffset")
            s_dword(value=0x00, name="CreateContextsLength")
            s_string("\x00", name="Buffer")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_create_response")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x05\x00', name="command")  # create need set command to 5
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x59\x00", name="StructureSize")
            s_group("OplockLevel", ["\x00", "\x01", "\x08", "\x09", "\xff"])
            s_byte(value=0x01, name="Flags")
            s_group("CreateAction",
                    ["\x00\x00\x00\x00", "\x01\x00\x00\x00", "\x02\x00\x00\x00", "\x03\x00\x00\x00"])
            s_qword(value=0x00, name="CreationTime")
            s_qword(value=0x00, name="LastAccessTime")
            s_qword(value=0x00, name="LastWriteTime")
            s_qword(value=0x00, name="ChangeTime")
            s_qword(value=0x00, name="AllocationSize")
            s_qword(value=0x00, name="EndofFile")
            s_dword(value=0x00, name="FileAttributes")
            s_dword(value=0x00, name="Reserved2")
            s_bit_field(value=0x00, width=128, name="FileId")
            s_dword(value=0x00, name="CreateContextsOffset")
            s_dword(value=0x00, name="CreateContextsLength")
            s_string("\x00", name="Buffer")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_echo_request")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x0d\x00', name="command")  # echo need set command to 0x0d
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x04\x00", name="StructureSize")
            s_word(value=0x00, name="Reserved")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_echo_response")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x0d\x00', name="command")  # echo need set command to 0x0d
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x04\x00", name="StructureSize")
            s_word(value=0x00, name="Reserved")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize('smb_error_response')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False)
        # s_block_end()
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_static(value='\0xaa\0x53\0x4d\0x42', name='protocol_id')
            s_static(value='\0x00\0x40', name="header_length")
            s_word(value=0x01, name="credit_charge", fuzzable=False)
            s_word(value=0x00, name="channel_sequence ", fuzzable=False)
            s_word(value=0x00, name="reserved_1", fuzzable=False)
            s_word(value=0x02, name="command", fuzzable=False)
            s_word(value=0x01, name="credits_granted", fuzzable=False)
            s_dword(value=0x01, name="flags ", fuzzable=False)
            s_dword(value=0x00, name="next_command", fuzzable=False)
            s_qword(value=0x00, name="message_id", fuzzable=False)
            s_qword(value=0x00, name="async_id", fuzzable=False)  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0x00, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_error_response_body"):
            s_static('\0x09\x00', name="structure_size")
            s_static("\0x00", name="error_context_count ")
            s_static("\0x00", name="reserved_2")
            ByteCount = random.randint(0, 101)
            s_dword(ByteCount, name="ByteCount ", fuzzable=False)
            s_random("sss", min_length=ByteCount, max_length=ByteCount, name="ErrorData")
    #     s_block_end("smb_error_response_body")
    #  s_block_end('smb3_content')

    s_initialize("SMB_flush_request")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x07\x00', name="command")  # flush need set command to 7
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x18\x00", name="StructureSize")
            s_word(value=0x00, name="Reserved1")
            s_dword(value=0x00, name="Reserved2")
            s_bit_field(value=0x00, width=128, name="FileId")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_flush_response")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x07\x00', name="command")  # flush need set command to 7
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x04\x00", name="StructureSize")
            s_word(value=0x00, name="Reserved")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_ioctl_request")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x0b\x00', name="command")  # ioctl need set command to 5
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x39\x00", name="StructureSize")
            s_word(value=0x00, name="Reserved")
            s_group("CtlCode", ["\x94\x01\x06\x00", "\x0c\x40\x11\x00", "\x18\x00\x11\x00", "\x17\xc0\x11\x00", \
                                "\xf2\x40\x14\x00", "\x64\x40\x14\x00", "\x78\x00\x14\x00", "\xbb\x41\x14\x00", \
                                "\xf2\x80\x14\x00", "\xd4\x01\x14\x00", "\xa4\x00\x09\x00", "\xb0\x01\x06\x00", \
                                "\x08\x82\x09\x00", "\x04\x02\x14\x00"])
            s_bit_field(value=0x00, width=128, name="FileId")
            s_dword(value=0x00, name="InputOffset")
            s_dword(value=0x00, name="InputCount")
            s_dword(value=0x00, name="MaxInputResponse")
            s_dword(value=0x00, name="OutputOffset")
            s_dword(value=0x00, name="OutputCount")
            s_dword(value=0x00, name="MaxOutputResponse")
            s_group("Flags", ["\x00\x00\x00\x00", "\x01\x00\x00\x00"])
            s_dword(value=0x00, name="Reserved2")
            s_string("\x00", name="Buffer")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_ioctl_response")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x0b\x00', name="command")  # ioctl need set command to 5
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x31\x00", name="StructureSize")
            s_word(value=0x00, name="Reserved")
            s_dword(value=0x00, name="CtlCode")
            s_bit_field(value=0x00, width=128, name="FileId")
            s_dword(value=0x00, name="InputOffset")
            s_dword(value=0x00, name="InputCount")
            s_dword(value=0x00, name="OutputOffset")
            s_dword(value=0x00, name="OutputCount")
            s_dword(value=0x00, name="Flags")
            s_dword(value=0x00, name="Reserved2")
            s_string("\x00", name="Buffer")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize('smb_logoff_request')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x02, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_logoff_request_body"):
            s_binary('0x040x00', name="structure_size")
            s_binary("0x000x00", name="reserved_2")
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('smb_logoff_response')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x02, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_logoff_response_body"):
            s_binary('0x040x00', name="structure_size")
            s_binary("0x000x00", name="reserved_2")
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('SMB_NEGOTIATE_Request')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x00, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("SMB_NEGOTIATE_Request_body"):
            s_static('\x24\x00', name="structure_size")
            dialect_count = random.randint(0, 101)
            s_word(dialect_count, name="reserved_2", fuzzable=False)
            s_word(0x00, name="security_mode")
            s_word(0x00, name="reserved_3")
            s_dword(0x00, name="capabilities")
            s_bit_field(value=0x00, width=128, name="client_guid ")
            s_qword(0x00, name="client_start_time ")  # 或者为 NegotiateContextOffset,NegotiateContextCount,Reserved2
            s_random("", min_length=0, max_length=64, step=8,
                     name="union")  # Dialects  Padding  NegotiateContextList  8-byte aligned
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('SMB_NEGOTIATE_Response')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x00, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("SMB_NEGOTIATE_Response_body"):
            s_static('\x41\x00', name="structure_size")
            s_word(0x00, name="security_mode")
            s_word(0x00, name="dialect_revision")
            s_word(0x00, name="negotiate_context_count")
            s_bit_field(value=0x00, width=128, name="server_guid")
            s_dword(0x00, name="capabilities")
            s_dword(0x00, name="max_transact_size ")
            s_dword(0x00, name="max_read_size")
            s_dword(0x00, name="max_write_size")
            s_qword(0x00, name="system_time")
            s_qword(0x00, name="server_start_time")
            s_word(0x00, name="security_buffer_offset")
            s_word(0x00, name="security_buffer_length")
            s_dword(0x00, name="negotiate_context_offset")
            s_random("", min_length=0, max_length=64, step=8,
                     name="union")  # Buffer   Padding  NegotiateContextList   8-byte aligned
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize("SMB_oplock_break_notification")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_static('\x12\x00', name="command")  # oplock_break need set command to 0x12
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x18\x00", name="StructureSize")
            s_group("OplockLevel", ["\x00", "\x01", "\x08"])
            s_byte(value=0x00, name="Reserved")
            s_word(value=0x00, name="Reserved2")
            s_bit_field(value=0x00, width=128, name="FileId")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_lease_break_notification")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_static('\x12\x00', name="command")  # oplock_break need set command to 0x12
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x2c\x00", name="StructureSize")
            s_word(value=0x00, name="NewEpoch")
            s_dword(value=0x01, name="Flags")
            s_bit_field(value=0x00, width=128, name="LeaseKey")
            s_group("CurrentLeaseState",
                    ["\x01\x00\x00\x00", "\x02\x00\x00\x00", "\x04\x00\x00\x00"])
            s_dword(value=0x01, name="NewLeaseState")
            s_dword(value=0x01, name="BreakReason")
            s_dword(value=0x01, name="AccessMaskHint")
            s_dword(value=0x01, name="ShareMaskHint")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_oplock_break_acknowledgment")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_static('\x12\x00', name="command")  # oplock_break need set command to 0x12
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x18\x00", name="StructureSize")
            s_group("OplockLevel", ["\x00", "\x01", "\x08"])
            s_byte(value=0x01, name="Reserved")
            s_dword(value=0x00, name="Reserved2")
            s_bit_field(value=0x00, width=128, name="FileId")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_lease_break_acknowledgment")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_static('\x12\x00', name="command")  # oplock_break need set command to 0x12
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x24\x00", name="StructureSize")
            s_word(value=0x00, name="Reserved")
            s_dword(value=0x00, name="Flags")
            s_bit_field(value=0x00, width=128, name="LeaseKey")
            s_group("LeaseState",
                    ["\x00\x00\x00\x00", "\x01\x00\x00\x00", "\x02\x00\x00\x00", "\x04\x00\x00\x00"])
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_oplock_break_response")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_static('\x12\x00', name="command")  # oplock_break need set command to 0x12
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x18\x00", name="StructureSize")
            s_group("OplockLevel", ["\x00", "\x01", "\x08"])
            s_byte(value=0x01, name="Reserved")
            s_dword(value=0x00, name="Reserved2")
            s_bit_field(value=0x00, width=128, name="FileId")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_lease_break_response")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_static('\x12\x00', name="command")  # oplock_break need set command to 0x12
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x24\x00", name="StructureSize")
            s_word(value=0x00, name="Reserved")
            s_dword(value=0x01, name="Flags")
            s_bit_field(value=0x00, width=128, name="LeaseKey")
            s_group("LeaseState",
                    ["\x00\x00\x00\x00", "\x01\x00\x00\x00", "\x02\x00\x00\x00", "\x04\x00\x00\x00"])
            s_qword(value=0x00, name="LeaseDuration")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_query_directory_request")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x0e\x00', name="command")  # query_directory need set command to 5
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x21\x00", name="StructureSize")
            s_group("FileInformationClass", ["\x01", "\x02", "\x26", "\x03", "\x25", "\x0c", "\x3c"])
            s_group("Flags", ["\x00", "\x01", "\x02", "\x04", "\x10"])
            s_dword(value=0x00, name="FileIndex")
            s_bit_field(value=0x00, width=128, name="FileId")
            s_word(value=0x00, name="FileNameOffset")
            s_word(value=0x00, name="FileNameLength")
            s_dword(value=0x00, name="OutputBufferLength")
            s_string("\x00", name="Buffer")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_query_directory_response")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x0e\x00', name="command")  # query_directory need set command to 5
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x09\x00", name="StructureSize")
            s_word(value=0x00, name="OutputBufferOffset")
            s_dword(value=0x00, name="OutputBufferLength")
            s_string("\x00", name="Buffer")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize('smb_QUERY_INFO_request')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x0010, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_QUERY_INFO_request_body"):
            s_binary('0x290x00', name="structure_size")
            s_byte(0x00, name="info_type")
            s_byte(0x00, name="file_info_class")
            s_dword(0x00, name="output_buffer_length")
            s_word(0x00, name="input_buffer_offset")
            s_word(0x00, name="reserved_2")
            s_dword(0x00, name="input_buffer_length")
            s_dword(0x00, name="additional_information")
            s_dword(0x00, name="flags")
            s_bit_field(value=0x00, width=128, name="fileId")
            s_random("aaaa", min_length=4, max_length=100,
                     name="buffer")

        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('smb_QUERY_INFO_response')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x0010, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_QUERY_INFO_response_body"):
            s_binary('0x090x00', name="structure_size")
            s_word(0x48, name="output_buffer_offset", fuzzable=False)
            output_buffer_length = random.randint(0, 101)
            s_dword(output_buffer_length, name="output_buffer_length", fuzzable=False)
            s_random("\x00" * output_buffer_length, min_length=output_buffer_length, max_length=output_buffer_length,
                     name="buffer")

        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize("SMB_read_request")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x08\x00', name="command")  # read need set command to 8
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x31\x00", name="StructureSize")
            s_byte(value=0x00, name="Padding")
            s_group("Flags", ["\x00", "\x01", "\x02"])
            s_dword(value=0x00, name="Length")
            s_qword(value=0x00, name="Offset")
            s_bit_field(value=0x00, width=128, name="FileId")
            s_dword(value=0x00, name="MinimumCount")
            s_group("Channel",
                    ["\x00\x00\x00\x00", "\x01\x00\x00\x00", "\x02\x00\x00\x00"])  # for SMB2 2.0.2 and 2.1
            s_dword(value=0x00, name="RemainingBytes")  # For the SMB2 3.x
            s_word(value=0x00, name="ReadChannelInfoOffset")  # For the SMB2 3.x
            s_word(value=0x00, name="ReadChannelInfoLength")  # For the SMB2 3.x
            s_string("\x00", name="Buffer")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_read_response")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x08\x00', name="command")  # read need set command to 8
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x11\x00", name="StructureSize")
            s_byte(value=0x01, name="DataOffset")
            s_byte(value=0x01, name="Reserved")
            s_dword(value=0x00, name="DataLength")
            s_dword(value=0x00, name="DataRemaining")
            s_dword(value=0x00, name="Reserved2/Flags")
            s_string("\x00", name="Buffer")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize('smb_SESSION_SETUP_request')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x01, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_SESSION_SETUP_request_body"):
            s_static('\x19\x00', name="structure_size")
            s_byte(0x00, name='flags')
            s_byte(0x00, name='security_mode')
            s_dword(0x00, name="capabilities")
            s_dword(0x00, name="channel")
            s_word(0x58, name="security_buffer_offset", fuzzable=False)
            security_buffer_length = random.randint(0, 101)
            s_word(security_buffer_length, name="security_buffer_length", fuzzable=False)
            s_qword(0x00, name="previous_session_id", fuzzable=False)
            s_random("a" * security_buffer_length, min_length=security_buffer_length, max_length=security_buffer_length,
                     name="union")
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('smb_SESSION_SETUP_response')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x01, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_SESSION_SETUP_response_body"):
            s_static('\x09\x00', name="structure_size")
            s_word(0x00, name='session_flags')
            s_word(0x48, name="security_buffer_offset", fuzzable=False)
            security_buffer_length = random.randint(0, 101)
            s_word(security_buffer_length, name="security_buffer_length", fuzzable=False)
            s_random("a" * security_buffer_length, min_length=security_buffer_length, max_length=security_buffer_length,
                     name="buffer")
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('smb_SET_INFO_request')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x11, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_SET_INFO_request_body"):
            s_binary('0x210x00', name="structure_size")
            s_byte(0x00, name="info_type")
            s_byte(0x00, name="file_info_class")
            buffer_length = random.randint(0, 101)
            s_dword(buffer_length, name="buffer_length")
            s_word(96, name="buffer_offset", fuzzable=False)
            s_word(0x00, name="reserved_2")
            s_dword(0x00, name="additional_information")
            s_bit_field(value=0x00, width=128, name="file_id")
            s_random("\x00" * buffer_length, min_length=buffer_length, max_length=buffer_length,
                     name="buffer")
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('smb_SET_INFO_response')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x11, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_SET_INFO_response_body"):
            s_binary('0x040x00', name="structure_size")
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('smb_TRANSFORM_HEADER')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfd0x530x4d0x42', name='protocol_id')
            s_bit_field(value=0x00, width=128, name="signature")
            s_bit_field(value=0x00, width=128, name="nonce")
            s_bit_field(value=0x00, width=88, name="AES_CCM_Nonce")
            s_bit_field(value=0x00, width=40, name="reserved_1")
            s_bit_field(value=0x00, width=96, name="AES_GCM_Nonce")
            s_dword(0x00, name="reserved_2")
            s_dword(0x00, name="OriginalMessageSize")
            s_word(0x00, name="reserved_3")
            s_word(0x00, name="flags")

        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('smb_TREE_CONNECT_request')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x03, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_TREE_CONNECT_request_body"):
            s_binary('0x090x00', name="structure_size")
            s_word(0x00, name="flags")
            s_word(0x48, name="path_offset")
            path_length = random.randint(0, 101)
            s_word(path_length, name="path_length", fuzzable=False)
            s_random("\x00" * path_length, min_length=path_length, max_length=path_length, name="buffer")
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('smb_TREE_CONNECT_response')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x03, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_TREE_CONNECT_response_body"):
            s_binary('0x010x00', name="structure_size")
            s_byte(0x02, name="share_type ")
            s_byte(0x00, name="reserved_2")
            s_dword(0x00, name="share_flags")
            s_dword(0x00, name="capabilities")
            s_dword(0x00, name="maximal_access")
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('smb_TREE_DISCONNECT_request')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x04, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_TREE_DISCONNECT_request_body"):
            s_binary('0x040x00', name="structure_size")
            s_binary("0x000x00", name="reserved_2")
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('smb_TREE_DISCONNECT_response')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfe0x530x4d0x42', name='protocol_id')
            s_word(value=0x40, name="header_length", fuzzable=False)
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence ")
            s_word(value=0x00, name="reserved_1")
            s_word(value=0x04, name="command")
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags ")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        #   s_block_end('smb3_header')
        with s_block("smb_TREE_DISCONNECT_response_body"):
            s_binary('0x040x00', name="structure_size")
            s_binary("0x000x00", name="reserved_2")
        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize("SMB_write_request")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x09\x00', name="command")  # write need set command to 9
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x00, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x31\x00", name="StructureSize")
            s_word(value=0x00, name="DataOffset")
            s_dword(value=0x00, name="Length")
            s_qword(value=0x00, name="Offset")
            s_bit_field(value=0x00, width=128, name="FileId")
            s_dword(value=0x00, name="Channel")
            s_dword(value=0x00, name="RemainingBytes")
            s_word(value=0x00, name="WriteChannelInfoOffset")
            s_word(value=0x00, name="WriteChannelInfoLength")
            s_dword(value=0x00, name="Flags")
            s_string("\x00", name="Buffer")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize("SMB_write_response")
    if (s_block_start("NetBIOS")):
        s_static("\x00", name="message type")
        s_size(name="packet length", block_name="SMB2", length=3, inclusive=False, fuzzable=False, endian=">")
    s_block_end("NetBIOS")
    if (s_block_start("SMB2")):
        if (s_block_start("SMB2 header")):
            s_static('\xfe\x53\x4d\x42', name='protocol_id')
            s_static('\x40\x00', name="header_length")
            s_word(value=0x01, name="credit_charge")
            s_word(value=0x00, name="channel_sequence")
            s_word(value=0x00, name="reserved_1")
            s_static('\x09\x00', name="command")  # write need set command to 9
            s_word(value=0x01, name="credits_granted")
            s_dword(value=0x01, name="flags")
            s_dword(value=0x00, name="next_command")
            s_qword(value=0x00, name="message_id")
            s_qword(value=0x00, name="async_id")  # 为sync , 分为 Reserved (4 bytes)  TreeId (4 bytes)
            s_qword(value=0xbb, name="session_id", fuzzable=False)
            s_bit_field(value=0x00, width=128, name="signature")
        s_block_end("SMB2 header")
        if (s_block_start("SMB2 body")):
            s_static("\x11\x00", name="StructureSize")
            s_word(value=0x00, name="Reserved")
            s_dword(value=0x00, name="Count")
            s_dword(value=0x00, name="Remaining")
            s_word(value=0x00, name="WriteChannelInfoOffset")
            s_word(value=0x00, name="WriteChannelInfoLength")
        s_block_end("SMB2 body")
    s_block_end("SMB2")

    s_initialize('SMB_COMPRESSION_TRANSFORM_HEADER_CHAINED')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfc0x530x4d0x42', name='protocol_id')
            s_dword(value=0x00, name="OriginalCompressedSegmentSize", fuzzable=False)
            s_random("\x00\x00\x00\x00", min_length=4, max_length=100,
                     name="CompressionPayloadHeader")

        #  s_block_end()
    # s_block_end('smb3_content')

    s_initialize('SMB_COMPRESSION_TRANSFORM_HEADER_UNCHAINED')
    with s_block('netbios_session_service'):  # netbios_header
        s_static(value='\x00', name='message_type')
        s_size(block_name="smb3_content", length=3, name='netbios_length', fuzzable=False, endian=">")
    # s_block_end('netbios_session_service')
    with s_block('smb3_content'):
        with s_block('smb3_header'):
            s_binary(value='0xfc0x530x4d0x42', name='protocol_id')
            s_dword(value=0x00, name="OriginalCompressedSegmentSize ")
            s_word(value=0x00, name="CompressionAlgorithm")
            s_word(0x00, name="flags")
            s_dword(0x00, name="offset")

        #  s_block_end()
    # s_block_end('smb3_content')

    sess.connect(s_get("SMB_COMPRESSION_TRANSFORM_HEADER_UNCHAINED"))

    sess.connect(s_get("SMB_COMPRESSION_TRANSFORM_HEADER_CHAINED"))

    # sess.connect(s_get("SMB_write_request"))
    sess.connect(s_get("SMB_write_response"))

    sess.connect(s_get("smb_TREE_DISCONNECT_response"))

    sess.connect(s_get("smb_TREE_DISCONNECT_request"))

    sess.connect(s_get("smb_TREE_CONNECT_response"))

    sess.connect(s_get("smb_TREE_CONNECT_request"))

    sess.connect(s_get("smb_TRANSFORM_HEADER"))

    sess.connect(s_get("smb_SET_INFO_response"))

    sess.connect(s_get("smb_SET_INFO_request"))

    sess.connect(s_get("smb_SESSION_SETUP_response"))

    sess.connect(s_get("smb_SESSION_SETUP_request"))

    sess.connect(s_get("SMB_read_request"))
    sess.connect(s_get("SMB_read_response"))

    sess.connect(s_get("smb_QUERY_INFO_response"))

    sess.connect(s_get("smb_QUERY_INFO_request"))

    sess.connect(s_get("SMB_query_directory_request"))
    sess.connect(s_get("SMB_query_directory_response"))

    sess.connect(s_get("SMB_oplock_break_notification"))
    sess.connect(s_get("SMB_lease_break_notification"))
    sess.connect(s_get("SMB_oplock_break_acknowledgment"))
    sess.connect(s_get("SMB_lease_break_acknowledgment"))
    sess.connect(s_get("SMB_oplock_break_response"))
    sess.connect(s_get("SMB_lease_break_response"))

    sess.connect(s_get("SMB_NEGOTIATE_Response"))

    sess.connect(s_get("SMB_NEGOTIATE_Request"))

    sess.connect(s_get("smb_logoff_response"))

    sess.connect(s_get("smb_logoff_request"))

    # sess.connect(s_get("SMB_ioctl_request"))
    sess.connect(s_get("SMB_ioctl_response"))

    sess.connect(s_get("SMB_flush_request"))
    sess.connect(s_get("SMB_flush_response"))

    sess.connect(s_get("smb_error_response"))

    sess.connect(s_get("SMB_echo_request"))
    sess.connect(s_get("SMB_echo_response"))

    sess.connect(s_get("SMB_create_request"))
    sess.connect(s_get("SMB_create_response"))

    sess.connect(s_get("SMB_close_request"))
    sess.connect(s_get("SMB_close_response"))

    sess.connect(s_get("smb_CHANGE_NOTIFY_response"))

    sess.connect(s_get("smb_CHANGE_NOTIFY_request"))

    sess.connect(s_get("SMB_cancel_response"))
    sess.fuzz()


if __name__ == "__main__":
    # target_ip = "127.0.0.1"
    target_ip = "192.168.72.1"
    start_cmds = []
    proc_name = ""
    pport = 139
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
