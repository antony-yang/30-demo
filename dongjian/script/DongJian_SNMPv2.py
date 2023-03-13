from DongJian import *
param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 161
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
	"proto": "SNMPv2"
}
SNMP_Error_code = {
    0: [0, 'noError (0)'],
    1: [1, 'tooBig (1)'],
    2: [2, 'noSuchName (2)'],
    3: [3, 'badValue (3)'],
    4: [4, 'readOnly (4)'],
    5: [5, 'genErr (5)'],
    6: [6, 'noAccess (6)'],
    7: [7, 'wrongType (7)'],
    8: [8, 'wrongLength (8)'],
    9: [9, 'wrongEncoding (9)'],
    10: [10, 'wrongValue (10)'],
    11: [11, 'noCreation (11)'],
    12: [12, 'inconsistentValue (12)'],
    13: [13, 'resourceUnavailable (13)'],
    14: [14, 'commitFailed (14)'],
    15: [15, 'undoFailed (15)'],
    16: [16, 'authorizationError (16)'],
    17: [17, 'notWritable (17)'],
    18: [18, 'inconsistentName (18)']
}

SNMP_TRAP_code = {
    0: [0, 'coldStart (0)'],
    1: [1, 'warmStart (1)'],
    2: [2, 'linkDown (2)'],
    3: [3, 'linkUp (3)'],
    4: [4, 'authenticationFailure (4)'],
    5: [5, 'egpNeighborLoss (5)'],
    6: [6, 'enterpriseSpecific (6)'],
}


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    session = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto='udp')
        ),
        **kwargs
    )

    s_initialize("snmp")
    s_static('\x30')
    s_size(block_name='snmp header', length=1, endian='>', inclusive=True, name='snmp len')
    if s_block_start('snmp header'):
        s_static('\x02\x01')
        s_static(name='version', value='\x01')
        s_static('\x04\x06')
        s_group(name='community', values=['\x70\x75\x62\x6c\x69\x63', '\x70\x72\x69\x76\x61\x74\x65'],
                default_value='\x70\x75\x62\x6c\x69\x63')
        s_group(name='pdu type', values=['\xa0', '\xa1', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6', '\xa7'])
        s_size(block_name='header', length=1, endian='>', inclusive=True, name='header len')
        if s_block_start('header'):
            s_static('\x02\x02')
            s_word(name='request id', value=8411, fuzzable=True, endian='>')
            s_static('\x02\x01')
            s_group(name='error status', values=['\x00', '\x01', '\x02', '\x03', '\x04', '\x05'], default_value='\x00')
            s_static('\x02\x01')
            s_bit(name='error index', value=0, width=1)
            s_static('\x30')
            s_size(block_name='variable', length=1, endian='>', inclusive=False, name='variable len')
            if s_block_start('variable'):
                s_static('\x30')
                s_size(block_name='variable value', length=1, endian='>', inclusive=False, name='variable value len')
                if s_block_start('variable value'):
                    s_static('\x06')
                    s_size(block_name='object', length=1, endian='>', inclusive=False, name='object len')
                    if s_block_start('object'):
                        # fuzzable oid
                        s_group(name='oid', values=['\x2b\x06\x01\x02\x01\x01',
                                                    '\x2b\x06\x01\x02\x01\x01\x01\x00'
                                                    '\x2b\x06\x01\x02\x01\x01\x01\x00',
                                                    '\x2b\x06\x01\x02\x01\x01\x03\x00',
                                                    '\x2b\x06\x01\x02\x01\x01\x04\x00',
                                                    '\x2b\x06\x01\x02\x01\x01\x05\x00',
                                                    '\x2b\x06\x01\x02\x01\x01\x06\x00',
                                                    '\x2b\x06\x01\x02\x01\x01\x07\x00',
                                                    '\x2b\x06\x01\x02\x01\x19\x04\x02\x01\x02',
                                                    '\x2b\x06\x01\x02\x01\x19\x06\x03\x01\x02',
                                                    ],
                                default_value='\x2b\x06\x01\x02\x01\x01')
                        # s_static('\x05\x00')
                    s_block_end('object')
                    # fuzzable oid value
                    s_static(value='\x05\x00', name='value')
                s_block_end('variable value')
            s_block_end('variable')
        s_block_end('header')
    s_block_end('snmp header')

    # s_initialize('snmp trap')
    # s_static('\x30')
    # s_size(block_name='snmp trap', length=1, endian='>', inclusive=False, name='trap len',fuzzable=False)
    # if s_block_start('snmp trap'):
    #     s_static('\x02\x01')
    #     s_static(name='version', value='\x01')
    #     s_static('\x04\x06')
    #     s_group(name='community1', values=['\x70\x75\x62\x6c\x69\x63', '\x70\x72\x69\x76\x61\x74\x65'],
    #             default_value='\x70\x75\x62\x6c\x69\x63')
    #     s_static(name='pdu trap', value='\xa4')
    #     s_size(block_name='trap', length=1, endian='>', inclusive=False, name='trapdata len',fuzzable=False)
    #     if s_block_start('trap'):
    #         s_static('\x06')
    #         s_size(block_name='enterprise', length=1, endian='>', inclusive=False, name='enterprise len',fuzzable=False)
    #         if s_block_start('enterprise'):
    #             s_group(name='enter', values=['\x2b\x06\x01\x04\x01\x01', '\x2b\x06\x01\x04\x01\x01\x01\x00'])
    #         s_block_end('enterprise')
    #         s_static('\x40')
    #         s_size(block_name='agent-addr', length=1, endian='>', inclusive=False, name='agent len',fuzzable=False)
    #         if s_block_start('agent-addr'):
    #             s_static('\x0a\x01\x00\x64')  # agent ip address
    #         s_block_end('agent-addr')
    #         s_static('\x02\x01')
    #         s_group(name='trap type', values=['\x02'])
    #         # s_group(name='trap type', values=['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06'])
    #         s_static('\x02\x01')
    #         s_group(name='specific', values=['\x03'])
    #         s_static('\x43')
    #         s_size(block_name='time', length=1, endian='>', inclusive=False, name='time len',fuzzable=False)
    #         if s_block_start('time'):
    #             s_word(value=1000, endian='>', fuzzable=False)
    #         s_block_end('time')
    #         s_static('\x30')
    #         s_size(block_name='trap var all', length=1, endian='>', inclusive=False, name='trapvar len',fuzzable=False)
    #         if s_block_start('trap var all'):
    #             s_static('\x30')
    #             s_size(block_name='trap object name', length=1, endian='>', inclusive=False, name='trap object len',fuzzable=False)
    #             if s_block_start('trap object name'):
    #                 s_static('\x06')
    #                 s_size(block_name='object iso', length=1, endian='>', inclusive=False, name='object iso len',fuzzable=False)
    #                 if s_block_start('object iso'):
    #                     s_group(name='trap iso', values=['\x2b\x06\x01\x09\x09\x2c\x01\x02\x01'])
    #                 s_block_end('object iso')
    #                 s_static('\x02\x01')
    #                 s_static('\x0c', name='integer32')
    #             s_block_end('trap object name')
    #
    #         # s_static('\x30')
    #         # s_size(block_name='trap var1', length=1, endian='>', inclusive=False, name='trapvar1 len')
    #         # if s_block_start('trap var1'):
    #             s_static('\x30')
    #             s_size(block_name='trap object1 name', length=1, endian='>', inclusive=False, name='trap object1 len',fuzzable=False)
    #             if s_block_start('trap object1 name'):
    #                 s_static('\x06')
    #                 s_size(block_name='object1 iso', length=1, endian='>', inclusive=False, name='object1 iso len',fuzzable=False)
    #                 if s_block_start('object1 iso'):
    #                     s_group(name='trap1 iso', values=['\x2b\x04\x01\x02\x03\x01'])
    #                 s_block_end('object1 iso')
    #                 s_static('\x04')
    #                 s_size(block_name='trap value2', length=1, endian='>', inclusive=False, name='trap value2 len',fuzzable=False)
    #                 if s_block_start('trap value2'):
    #                     # s_group(name='ttt', values=['\x74\x65\x73\x74\x5f\x73\x6e\x6d\x70\x74\x72\x61\x70'])
    #                     s_string('11111', name='trap value')
    #                 s_block_end('trap value2')
    #                 # s_string('11111', name='trap value', max_len=13)
    #             s_block_end('trap object1 name')
    #         s_block_end('trap var all')
    #         # s_block_end('trap var1')
    #     s_block_end('trap')
    #     # s_group(name='pdu type', values=['\xa0', '\xa1', '\xa2', '\xa3'], default_value='\xa1')
    # s_block_end('snmp trap')

    # session.connect(s_get("snmp trap"))
    session.connect(s_get("snmp"))
    session.fuzz()

    # def snmp_get():


if __name__ == "__main__":
    start_cmd = [""]
    proc_name = ""
    target_ip = "127.0.0.1"
    pport = 161
    dport = 26002
    fuzz(start_cmd, proc_name, target_ip, pport, dport, script_start=True)
