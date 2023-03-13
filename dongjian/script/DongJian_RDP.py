
from DongJian import *
import random
import asn1tools
import sys
import os

MCSPDUs = asn1tools.compile_files('../script/MCSPDUs.asn', codec='per')

param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 3389
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
	"proto": "RDP"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
        ),
        **kwargs
    )

    s_initialize("RDP_Client_MCS_Attach_User_Request_PDU")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")

        s_static("\x02", name="length")
        s_static("\xf0", name="PDU Type")  # data transfer code
        s_static("\x80", name="Destination reference")

        channelId_list = [1007, 1003, 1004, 1005, 1006]
        result_list = [
            'rt-successful',
            'rt-domain-merging',
            'rt-domain-not-hierarchical',
            'rt-no-such-channel',
            'rt-no-such-domain',
            'rt-no-such-user',
            'rt-not-admitted',
            'rt-other-user-id',
            'rt-parameters-unacceptable',
            'rt-token-not-available',
            'rt-token-not-possessed',
            'rt-too-many-channels',
            'rt-too-many-tokens',
            'rt-too-many-users',
            'rt-unspecified-failure',
            'rt-user-rejected'
        ]

        AttachUserRequest = MCSPDUs.encode('AttachUserRequest', {

        })
        s_random(AttachUserRequest, name='mcsCJcf ', max_length=1, min_length=1)

    s_block_end("request")

    s_initialize("RDP_Client_MCS_Channel_Join_Request_PDU")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")

        s_static("\x02", name="length")
        s_static("\xf0", name="PDU Type")  # data transfer code
        s_static("\x80", name="Destination reference")

        channelId_list = [1007, 1003, 1004, 1005, 1006]
        result_list = [
            'rt-successful',
            'rt-domain-merging',
            'rt-domain-not-hierarchical',
            'rt-no-such-channel',
            'rt-no-such-domain',
            'rt-no-such-user',
            'rt-not-admitted',
            'rt-other-user-id',
            'rt-parameters-unacceptable',
            'rt-token-not-available',
            'rt-token-not-possessed',
            'rt-too-many-channels',
            'rt-too-many-tokens',
            'rt-too-many-users',
            'rt-unspecified-failure',
            'rt-user-rejected'
        ]

        ChannelJoinRequest = MCSPDUs.encode('ChannelJoinRequest', {
            # 'result': result_list[random.randint(0, 14)],
            'initiator': random.randint(0, sys.maxsize),
            # 'requested': channelId_list[random.randint(0, 4)],
            'channelId': channelId_list[random.randint(0, 4)]

        })
        s_random(ChannelJoinRequest, name='mcsCJrq', max_length=5, min_length=5)
        print(ChannelJoinRequest)

    s_block_end("request")

    s_initialize("RDP_Client_MCS_Erect_Domain_Request_PDU")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")

        s_static("\x02", name="length")
        s_static("\xf0", name="PDU Type")  # data transfer code
        s_static("\x80", name="Destination reference")

        channelId_list = [1007, 1003, 1004, 1005, 1006]
        result_list = [
            'rt-successful',
            'rt-domain-merging',
            'rt-domain-not-hierarchical',
            'rt-no-such-channel',
            'rt-no-such-domain',
            'rt-no-such-user',
            'rt-not-admitted',
            'rt-other-user-id',
            'rt-parameters-unacceptable',
            'rt-token-not-available',
            'rt-token-not-possessed',
            'rt-too-many-channels',
            'rt-too-many-tokens',
            'rt-too-many-users',
            'rt-unspecified-failure',
            'rt-user-rejected'
        ]

        ErectDomainRequest = MCSPDUs.encode('ErectDomainRequest', {
            "subHeight": random.randint(0, sys.maxsize),
            "subInterval": random.randint(0, sys.maxsize)
        })
        s_random(ErectDomainRequest, name='mcsEDrq ', max_length=5, min_length=5)
        print(ErectDomainRequest)

    s_block_end("request")

    s_initialize("RDP_Server_MCS_Attach_User_Confirm_PDU")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")

        s_static("\x02", name="length")
        s_static("\xf0", name="PDU Type")  # data transfer code
        s_static("\x80", name="Destination reference")

        channelId_list = [1007, 1003, 1004, 1005, 1006]
        result_list = [
            'rt-successful',
            'rt-domain-merging',
            'rt-domain-not-hierarchical',
            'rt-no-such-channel',
            'rt-no-such-domain',
            'rt-no-such-user',
            'rt-not-admitted',
            'rt-other-user-id',
            'rt-parameters-unacceptable',
            'rt-token-not-available',
            'rt-token-not-possessed',
            'rt-too-many-channels',
            'rt-too-many-tokens',
            'rt-too-many-users',
            'rt-unspecified-failure',
            'rt-user-rejected'
        ]

        AttachUserConfirm = MCSPDUs.encode('AttachUserConfirm', {
            'result': result_list[random.randint(0, 14)],
            'initiator': random.randint(0, sys.maxsize)
            # 'requested': channelId_list[random.randint(0, 4)],
            # 'channelId': channelId_list[random.randint(0, 4)]

        })
        s_random(AttachUserConfirm, name='mcsCJcf ', max_length=4, min_length=4)
        print(AttachUserConfirm)

    s_block_end("request")

    s_initialize("Server_MCS_Channel Join_Confirm_PDU")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")

        s_static("\x02", name="length")
        s_static("\xf0", name="PDU Type")  # data transfer code
        s_static("\x80", name="Destination reference")

        channelId_list = [1007, 1003, 1004, 1005, 1006]
        result_list = [
            'rt-successful',
            'rt-domain-merging',
            'rt-domain-not-hierarchical',
            'rt-no-such-channel',
            'rt-no-such-domain',
            'rt-no-such-user',
            'rt-not-admitted',
            'rt-other-user-id',
            'rt-parameters-unacceptable',
            'rt-token-not-available',
            'rt-token-not-possessed',
            'rt-too-many-channels',
            'rt-too-many-tokens',
            'rt-too-many-users',
            'rt-unspecified-failure',
            'rt-user-rejected'
        ]

        ChannelJoinConfirm = MCSPDUs.encode('ChannelJoinConfirm', {
            'result': result_list[random.randint(0, 14)],
            'initiator': random.randint(0, sys.maxsize),
            'requested': channelId_list[random.randint(0, 4)],
            'channelId': channelId_list[random.randint(0, 4)]

        })
        s_random(ChannelJoinConfirm, name='mcsCJcf ', max_length=8, min_length=8)
        print(ChannelJoinConfirm)

    s_block_end("request")

    # with Routing Token/Cookie
    s_initialize("Client_MCC_Connection_Request_PDU")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")
        if (s_block_start("x224")):
            s_static("\x02", name="length")
            s_static("\xf0", name="PDU Type")  # data transfer code
            s_static("\x80", name="Destination reference")
            # s_word(value=0x00, name="Destination reference")
        s_block_end("x224")
        s_static('\x7f\x65')  # T.125 Request flag
        s_static('\x82')
        s_size(name="connect-initial-length", block_name="T.125", length=2, inclusive=False, fuzzable=False, endian=">")
        if (s_block_start("T.125", group='upwardFlag')):
            s_static('\x04\x01')
            # s_static("\x01", name="callingDomainSeletor")
            s_byte(value=0x01, name="callingDomainSeletor")
            s_static('\x04\x01')
            # s_static("\x01", name="calledDomainSeletor")
            s_byte(value=0x01, name="calledDomainSeletor")
            s_static('\x01\x01')
            s_group(name="upwardFlag", values=['\xff', '\x00'])
            if (s_block_start("targetParameters")):
                # s_word(value=0x00, name="blank4")
                s_static('\x30\x19')
                s_static('\x02\x01')
                # s_static('\x22', name="MaxChannelIds1")
                s_byte(value=0x22, name="MaxChannelIds1")
                s_static('\x02\x01')
                # s_static('\x02', name="MaxUserIds1")
                s_byte(value=0x02, name="MaxUserIds1")
                s_static('\x02\x01')
                # s_static('\x00', name="MaxTokenIds1")
                s_byte(value=0x00, name="MaxTokenIds1")
                s_static('\x02\x01')
                # s_static('\x01', name="NumPriorities1")
                s_byte(value=0x01, name="NumPriorities1")
                s_static('\x02\x01')
                # s_static('\x00', name="MinThroughput1")
                s_byte(value=0x00, name="MinThroughput1")
                s_static('\x02\x01')
                # s_static('\x01', name="MaxHeight1")
                s_byte(value=0x01, name="MaxHeight1")
                s_static('\x02\x02')
                # s_static('\xff\xff', name="MaxMCSPDUsize1")
                s_word(value=0xffff, name="MaxMCSPDUsize1")
                s_static('\x02\x01')
                s_static("\x02", name="ProtocolVersion1")
            s_block_end("targetParameters")
            if (s_block_start("minumuParameters")):
                # s_dword(value=0x00, name="blank12")
                s_static('\x30\x19')
                s_static('\x02\x01')
                # s_static('\x01', name="MaxChannelIds2")
                s_byte(value=0x01, name="MaxChannelIds2")
                s_static('\x02\x01')
                # s_static('\x01', name="MaxUserIds2")
                s_byte(value=0x01, name="MaxUserIds2")
                s_static('\x02\x01')
                # s_static('\x01', name="MaxTokenIds2")
                s_byte(value=0x01, name="MaxTokenIds2")
                s_static('\x02\x01')
                # s_static('\x01', name="NumPriorities2")
                s_byte(value=0x01, name="NumPriorities2")
                s_static('\x02\x01')
                # s_static('\x00', name="MinThroughput2")
                s_byte(value=0x00, name="MinThroughput2")
                s_static('\x02\x01')
                # s_static('\x01', name="MaxHeight2")
                s_byte(value=0x01, name="MaxHeight2")
                s_static('\x02\x02')
                # s_static('\x04\x20', name="MaxMCSPDUsize2")
                s_word(value=0x2004, name="MaxMCSPDUsize2")
                s_static('\x02\x01')
                s_static("\x02", name="ProtocolVersion2")
            s_block_end("minumuParameters")
            if (s_block_start("maximumParameters")):
                # s_dword(value=0x00, name="blank20")
                s_static('\x30\x1c')
                s_static('\x02\x02')
                # s_static('\xff\xff', name="MaxChannelIds3")
                s_word(value=0xffff, name="MaxChannelIds3")
                s_static('\x02\x02')
                # s_static('\xfc\x17', name="MaxUserIds3")
                s_word(value=0x17fc, name="MaxUserIds3")
                s_static('\x02\x02')
                # s_static('\xff\xff', name="MaxTokenIds3")
                s_word(value=0xffff, name="MaxTokenIds3")
                s_static('\x02\x01')
                # s_static('\x01', name="NumPriorities3")
                s_byte(value=0x01, name="NumPriorities3")
                s_static('\x02\x01')
                # s_static('\x00', name="MinThroughput3")
                s_byte(value=0x00, name="MinThroughput3")
                s_static('\x02\x01')
                # s_static('\x01', name="MaxHeight3")
                s_byte(value=0x01, name="MaxHeight3")
                s_static('\x02\x02')
                # s_static('\xff\xff', name="MaxMCSPDUsize3")
                s_word(value=0xffff, name="MaxMCSPDUsize3")
                s_static('\x02\x01')
                s_static("\x02", name="ProtocolVersion3")
            s_block_end("maximumParameters")
            # userData is T.124
            s_static("\x04\x82")
            s_size(name="T.124-length", block_name="T.124", length=2, inclusive=False, fuzzable=False,
                   endian=">")
            if (s_block_start("T.124")):
                s_static("\x00\x05")
                s_static("\x00\x14\x7c\x00\x01")  # object: 0.0.20.124.0.1
                s_static("\x81\x62", name="connectPDULength")  # T.124-length -9 and first is 8
                s_static("\x00")
                s_static("\x08\x00", name="conferenceName")
                # s_word(value=0x00, name="conferenceName")
                s_static("\x10", name="terminationMethod")
                # s_byte(value=0x00, name="terminationMethod")
                s_static("\x00\x01")
                s_static("\xc0\x00\x44\x75\x63\x61", name="h221NonStandard")
                s_static("\x81\x54", name="RDPLength")  # connectPDULength - 14 and first is 8
                # userData is RDP
                if (s_block_start("RDP", group='version2')):
                    if (s_block_start("clientCoreData")):
                        s_static("\x01\xc0", name="headerType1")  # 0xC001 is CS_CORE
                        s_size(name="headerLength1", block_name="clientCoreData", length=2, inclusive=False,
                               fuzzable=False, endian="<")
                        s_group(name="version2",
                                values=['\x01\x00\x08\x00', '\x04\x00\x08\x00', '\x05\x00\x08\x00', '\x06\x00\x08\x00',
                                        '\x07\x00\x08\x00', '\x08\x00\x08\x00', '\x09\x00\x08\x00', '\x0a\x00\x08\x00',
                                        '\x0b\x00\x08\x00', '\x0c\x00\x08\x00', '\x0d\x00\x08\x00', '\x0e\x00\x08\x00'])
                        s_word(value=0x00, name="desktopWidth")
                        s_word(value=0x00, name="desktopHeight")
                        s_group(name="colorDepth", values=['\x00\xca', '\x01\xca'])
                        s_static(value="\x03\xaa", name="SASSequence")
                        s_dword(value=0x00, name="keyboardLayout")
                        s_dword(value=0x00, name="clientBuild")
                        s_bit_field(value=0x00, width=256, name="clientName")
                        s_group(name="keyboardType",
                                values=['\x01\x00\x00\x00', '\x02\x00\x00\x00', '\x03\x00\x00\x00', '\x04\x00\x00\x00',
                                        '\x05\x00\x00\x00', '\x06\x00\x00\x00', '\x07\x00\x00\x00', '\x08\x00\x00\x00'])
                        s_dword(value=0x00, name="keyboardSubType")
                        s_dword(value=0x00, name="keyboardFunctionKey")
                        s_bit_field(value=0x00, width=512, name="imeFileName")
                        s_group(name='postBeta2ColorDepth',
                                values=['\x00\xca', '\x01\xca', '\x02\xca', '\x03\xca', '\x04\xca'])
                        s_word(value=0x00, name="clientProductId")
                        s_dword(value=0x00, name="serialNumber")
                        s_group(name='highColorDepth',
                                values=['\x04\x00', '\x08\x00', '\x0f\x00', '\x10\x00', '\x18\x00'])
                        s_group(name='supportedColorDepths', values=['\x01\x00', '\x02\x00', '\x04\x00', '\x08\x00'])
                        s_group(name='earlyCapabilityFlags',
                                values=['\x01\x00', '\x02\x00', '\x04\x00', '\x08\x00', '\x10\x00',
                                        '\x20\x00', '\x40\x00', '\x80\x00', '\x00\x01', '\x00\x02',
                                        '\x00\x04'])
                        s_bit_field(value=0x00, width=512, name="clientDigProductId")
                        s_group(name='connectionType', values=['\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07'])
                        s_byte(value=0x00, name="pad1octet")
                    s_block_end("clientCoreData")

                    if (s_block_start("clientSecurityData")):
                        s_static("\x02\xc0", name="headerType2")  # 0xC002 is clientSecurityData flag
                        s_size(name="headerLength2", block_name="clientSecurityData", length=2, inclusive=False,
                               fuzzable=False, endian="<")
                        s_group(name="encryptionMethods",
                                values=['\x01\x00\x00\x00', '\x02\x00\x00\x00', '\x08\x00\x00\x00', '\x10\x00\x00\x00'])
                        s_dword(value=0x00, name="extEncryptionMethods")
                    s_block_end("clientSecurityData")

                    if (s_block_start("clientNetworkData")):
                        s_static("\x03\xc0", name="headerType3")  # 0xC003 is clientNetworkData flag
                        s_size(name="headerLength3", block_name="clientNetworkData", length=2, inclusive=False,
                               fuzzable=False, endian="<")
                        s_dword(value=0x00, name="channelCount")
                        s_qword(value=0x00, name="name")
                        s_group(name="options",
                                values=['\x00\x00\x00\x80', '\x00\x00\x00\x40', '\x00\x00\x00\x20', '\x00\x00\x00\x10',
                                        '\x00\x00\x00\x08', '\x00\x00\x00\x04', '\x00\x00\x00\x02', '\x00\x00\x80\x00',
                                        '\x00\x00\x40\x00', '\x00\x00\x20\x00', '\x00\x00\x10\x00'])
                    s_block_end("clientNetworkData")

                    if (s_block_start("clientClusterData")):
                        s_static("\x04\xc0", name="headerType4")  # 0xC004 is clientClusterData flag
                        s_size(name="headerLength4", block_name="clientClusterData", length=2, inclusive=False,
                               fuzzable=False, endian="<")
                        s_group(name="Flags1",
                                values=['\x01\x00\x00\x00', '\x3c\x00\x00\x00', '\x02\x00\x00\x00', '\x40\x00\x00\x00'])
                        s_dword(value=0x00, name="RedirectedSessionID")
                    s_block_end("clientClusterData")

                    if (s_block_start("clientMonitorData")):
                        s_static("\x05\xc0", name="headerType5")  # 0xC005 is clientMonitorData flag
                        s_size(name="headerLength5", block_name="clientMonitorData", length=2, inclusive=False,
                               fuzzable=False, endian="<")
                        s_dword(value=0x00, name="flags2")
                        s_dword(value=0x00, name="monitorCount")
                        s_dword(value=0x00, name="left")
                        s_dword(value=0x00, name="top")
                        s_dword(value=0x00, name="right")
                        s_dword(value=0x00, name="bottom")
                        s_dword(value=0x00, name="flags3")
                    s_block_end("clientMonitorData")

                    if (s_block_start("clientMessageChannelData")):
                        s_static("\x06\xc0", name="headerType6")  # 0xC006 is clientMessageChannelData flag
                        s_size(name="headerLength6", block_name="clientMessageChannelData", length=2, inclusive=False,
                               fuzzable=False, endian="<")
                        s_dword(value=0x00, name="flags4")
                    s_block_end("clientMessageChannelData")

                    if (s_block_start("clientMultitransportChannelData")):
                        s_static("\x0a\xc0", name="headerType7")  # 0xC00a is clientMultitransportChannelData flag
                        s_size(name="headerLength", block_name="clientMultitransportChannelData", length=2,
                               inclusive=False,
                               fuzzable=False, endian="<")
                        s_dword(value=0x00, name="flags5")
                    s_block_end("clientMultitransportChannelData")

                    if (s_block_start("clientMonitorExtendedData")):
                        s_static("\x08\xc0", name="headerType8")  # 0xC00a is clientMonitorExtendedData flag
                        s_size(name="headerLength7", block_name="clientMonitorExtendedData", length=2,
                               inclusive=False, fuzzable=False, endian="<")
                        s_dword(value=0x00, name="flags6")
                        s_dword(value=0x00, name="monitorAttributeSize")
                        s_dword(value=0x00, name="monitorCount2")
                        s_dword(value=0x00, name="physicalWidth")
                        s_dword(value=0x00, name="physicalHeight")
                        s_dword(value=0x00, name="orientation")
                        s_dword(value=0x00, name="desktopScaleFactor")
                        s_dword(value=0x00, name="deviceScaleFactor")
                    s_block_end("clientMonitorExtendedData")
                s_block_end("RDP")
            s_block_end("T.124")
        s_block_end("T.125")
    s_block_end("request")

    # with Routing Token/Cookie
    s_initialize("Client_MCC_Connection_Response_PDU")
    if (s_block_start("response")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="response", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")
        if (s_block_start("x224")):
            s_static("\x02", name="length")
            s_static("\xf0", name="PDU Type")  # data transfer code
            s_static("\x80", name="Destination reference")
            # s_word(value=0x00, name="Destination reference")
        s_block_end("x224")
        s_static('\x7f\x66')  # T.125 Response flag
        s_size(name="connect-initial-length", block_name="T.125", length=1, inclusive=False, fuzzable=False, endian=">")
        if (s_block_start("T.125")):
            s_static('\x0a\x01')
            s_byte(value=0x00, name="result")
            s_static('\x02\x01')
            s_byte(value=0x00, name="calledConnectI")
            if (s_block_start("domainParameters")):
                s_static('\x30\x1a')
                s_static('\x02\x01')
                s_byte(value=0x22, name="MaxChannelIds1")
                s_static('\x02\x01')
                s_byte(value=0x02, name="MaxUserIds1")
                s_static('\x02\x01')
                s_byte(value=0x00, name="MaxTokenIds1")
                s_static('\x02\x01')
                s_byte(value=0x01, name="NumPriorities1")
                s_static('\x02\x01')
                s_byte(value=0x00, name="MinThroughput1")
                s_static('\x02\x01')
                s_byte(value=0x01, name="MaxHeight1")
                s_static('\x02\x03\x00')
                s_word(value=0xffff, name="MaxMCSPDUsize1")
                s_static('\x02\x01')
                s_static("\x02", name="ProtocolVersion1")
            s_block_end("targetParameters")
            # userData is T.124
            s_static("\x04\x81")
            s_size(name="T.124-length", block_name="T.124", length=1, inclusive=False, fuzzable=False,
                   endian=">")
            if (s_block_start("T.124")):
                s_static("\x00\x05")
                s_static("\x00\x14\x7c\x00\x01")  # object: 0.0.20.124.0.1
                s_static("\x4c", name="connectPDULength")  # T.124-length -8
                s_static("\x14")
                s_static("\x71\x01", name="nodeId")
                s_static("\x01")
                s_static("\x01", name="tag")
                s_static("\x00\x01")
                s_static("\xc0\x00\x4d\x63\x44\x6e", name="h221NonStandard")
                s_static("\x3e", name="RDPLength")  # connectPDULength - 14
                # userData is RDP
                if (s_block_start("RDP", group="version2")):
                    # length is 16
                    if (s_block_start("serverCoreData")):
                        s_static("\x01\x0c", name="headerType1")  # 0x0C01 is Server Core Data flag
                        s_size(name="headerLength1", block_name="serverCoreData", length=2, inclusive=False,
                               fuzzable=False, endian="<")
                        s_group(name="version2",
                                values=['\x01\x00\x08\x00', '\x04\x00\x08\x00', '\x05\x00\x08\x00', '\x06\x00\x08\x00',
                                        '\x07\x00\x08\x00', '\x08\x00\x08\x00', '\x09\x00\x08\x00', '\x0a\x00\x08\x00',
                                        '\x0b\x00\x08\x00', '\x0c\x00\x08\x00', '\x0d\x00\x08\x00', '\x0e\x00\x08\x00'])
                        s_dword(value=0x00, name="clientRequestedProtocols")
                        s_group(name="earlyCapabilityFlags",
                                values=['\x01\x00\x00\x00', '\x02\x00\x00\x00', '\x04\x00\x00\x00'])
                    s_block_end("serverCoreData")

                    # length is 20
                    if (s_block_start("serverSecurityData", group="encryptionMethod")):
                        s_static("\x02\x0c", name="headerType2")  # 0x0C02 is Server Security Data flag
                        s_size(name="headerLength2", block_name="serverSecurityData", length=2, inclusive=False,
                               fuzzable=False, endian="<")
                        s_group(name="encryptionMethod",
                                values=['\x00\x00\x00\x00', '\x01\x00\x00\x00', '\x02\x00\x00\x00', '\x08\x00\x00\x00',
                                        '\x10\x00\x00\x00'])
                        s_group(name="encryptionLevel",
                                values=['\x00\x00\x00\x00', '\x01\x00\x00\x00', '\x02\x00\x00\x00', '\x03\x00\x00\x00',
                                        '\x04\x00\x00\x00'])
                        s_dword(value=0x00, name="serverRandomLen")
                        s_dword(value=0x00, name="serverCertLen")
                    s_block_end("serverSecurityData")
                    # length is 12
                    if (s_block_start("serverNetworkData")):
                        s_static("\x03\x0c", name="headerType3")  # 0x0C03 is Server Security Data flag
                        s_size(name="headerLength3", block_name="serverNetworkData", length=2, inclusive=False,
                               fuzzable=False, endian="<")
                        s_word(value=0x00, name="MCSChannelId")
                        s_word(value=0x00, name="channelCount")
                        s_word(value=0x00, name="channelIdArray")
                        s_word(value=0x00, name="Pad")
                    s_block_end("serverNetworkData")
                    # length is 6
                    if (s_block_start("serverMessageChannelData")):
                        s_static("\x04\x0c", name="headerType4")  # 0x0C04 is Server Message Channel Data flag
                        s_size(name="headerLength4", block_name="serverMessageChannelData", length=2, inclusive=False,
                               fuzzable=False, endian="<")
                        s_word(value=0x00, name="MCSChannelID2")
                    s_block_end("serverMessageChannelData")

                    # length is 8
                    if (s_block_start("serverMultitransportChannelData", group="flags2")):
                        s_static("\x08\x0c", name="headerType5")  # 0x0C08 is Server Multitransport Channel Data flag
                        s_size(name="headerLength5", block_name="serverMultitransportChannelData", length=2,
                               inclusive=False,
                               fuzzable=False, endian="<")
                        s_group(name="flags2",
                                values=['\x01\x00\x00\x00', '\x04\x00\x00\x00', '\x10\x00\x00\x00', '\x20\x00\x00\x00'])
                    s_block_end("serverMultitransportChannelData")

                s_block_end("RDP")
            s_block_end("T.124")
        s_block_end("T.125")
    s_block_end("response")

    s_initialize("Client X.224 Connection Confirm PDU(RDP_NEG_RSP)")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")
        if (s_block_start("x224Ccf_length")):
            s_size(name="x224Ccf_and_RDP_Length", block_name="x224Ccf_and_RDP", length=1, inclusive=False,
                   fuzzable=False, endian=">")
        s_block_end("x224Ccf_length")
        if (s_block_start("x224Ccf_and_RDP")):
            if (s_block_start("x224Ccf")):
                s_static("\xd0", name="PDU Type")  # CC Conect Confirm
                s_word(value=0x00, name="Destination reference")
                s_word(value=0x00, name="Source reference")
                s_byte(value=0x00, name="flags")
            s_block_end("x224Ccf")
            if (s_block_start("RDP", group='rdp_flags')):
                s_static("\x02", name="Type")  # TYPE_RDP_NEG_RSP
                s_group("rdp_flags", ['\x01', '\x02', '\x04', '\x08', '\x10'])
                s_static("\x08\x00", name="length")
                s_dword(value=0x00, name="requestedProtocols")
                # s_group("requestedProtocols", ['\x00\x00\x00\x00', '\x01\x00\x00\x00', '\x02\x00\x00\x00', '\x04\x00\x00\x00', '\x08\x00\x00\x00'])
            s_block_end("RDP")
        s_block_end("x224Ccf_and_RDP")
    s_block_end("request")

    s_initialize("Client X.224 Connection Confirm PDU(RDP_NEG_FAILURE)")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")
        if (s_block_start("x224Ccf_length")):
            s_size(name="x224Ccf_and_RDP_Length", block_name="x224Ccf_and_RDP", length=1, inclusive=False,
                   fuzzable=False, endian=">")
        s_block_end("x224Ccf_length")
        if (s_block_start("x224Ccf_and_RDP")):
            if (s_block_start("x224Ccf")):
                s_static("\xd0", name="PDU Type")  # CC Conect Confirm
                s_word(value=0x00, name="Destination reference")
                s_word(value=0x00, name="Source reference")
                s_byte(value=0x00, name="flags")
            s_block_end("x224Ccf")
            if (s_block_start("RDP", group='failureCode')):
                s_static("\x03", name="Type")  # TYPE_RDP_NEG_RSP
                s_byte(value=0x00, name="rdp_flags")
                s_static("\x08\x00", name="length")
                # s_dword(value=0x00, name="failureCode")
                s_group("failureCode", ['\x01\x00\x00\x00', '\x02\x00\x00\x00', '\x03\x00\x00\x00', '\x04\x00\x00\x00',
                                        '\x05\x00\x00\x00', '\x06\x00\x00\x00'])
            s_block_end("RDP")
        s_block_end("x224Ccf_and_RDP")
    s_block_end("request")

    # with Routing Token/Cookie
    s_initialize("Client X.224 Connection Request PDU(rdpNegReq)1")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")
        if (s_block_start("x224Crq_length")):
            s_size(name="x224Crq_and_RDP_Length", block_name="x224Crq_and_RDP", length=1, inclusive=False,
                   fuzzable=False, endian=">")
        s_block_end("x224Crq_length")
        if (s_block_start("x224Crq_and_RDP")):
            if (s_block_start("x224Crq")):
                s_static("\xe0", name="PDU Type")  # connection request
                s_word(value=0x00, name="Destination reference")
                s_word(value=0x00, name="Source reference")
                s_byte(value=0x0e, name="flags")
            s_block_end("x224Crq")
            if (s_block_start("RDP", group='requestedProtocols')):
                # if (s_block_start("RDP")):
                s_string("Cookie: mstshash=windows10", max_len=1441,
                         name="Routing Token/Cookie")  # with Routing Token/Cookie
                s_static("\x0d\x0a")
                s_static("\x01", name="Type")
                s_group("rdp_flags", ['\x01', '\x02', '\x08'])
                s_static("\x08\x00", name="length")
                s_group("requestedProtocols",
                        ['\x00\x00\x00\x00', '\x01\x00\x00\x00', '\x02\x00\x00\x00', '\x04\x00\x00\x00',
                         '\x08\x00\x00\x00'])
            s_block_end("RDP")
        s_block_end("x224Crq_and_RDP")
    s_block_end("request")

    # without Routing Token/Cookie
    s_initialize("Client X.224 Connection Request PDU(rdpNegReq)2")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")
        if (s_block_start("x224Crq_length")):
            s_size(name="x224Crq_and_RDP_Length", block_name="x224Crq_and_RDP", length=1, inclusive=False,
                   fuzzable=False, endian=">")
        s_block_end("x224Crq_length")
        if (s_block_start("x224Crq_and_RDP")):
            if (s_block_start("x224Crq")):
                s_static("\xe0", name="PDU Type")  # connection request
                s_word(value=0x00, name="Destination reference")
                s_word(value=0x00, name="Source reference")
                s_byte(value=0x0e, name="flags")
            s_block_end("x224Crq")
            if (s_block_start("RDP", group='requestedProtocols')):
                s_static("\x01", name="Type")
                s_group("rdp_flags", ['\x01', '\x02', '\x08'])
                s_static("\x08\x00", name="length")
                s_group("requestedProtocols",
                        ['\x00\x00\x00\x00', '\x01\x00\x00\x00', '\x02\x00\x00\x00', '\x04\x00\x00\x00',
                         '\x08\x00\x00\x00'])
            s_block_end("RDP")
        s_block_end("x224Crq_and_RDP")
    s_block_end("request")

    # with Routing Token/Cookie
    s_initialize("Client X.224 Connection Request PDU(rdpNegCorrelationInfo)1")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")
        if (s_block_start("x224Crq_length")):
            s_size(name="x224Crq_and_RDP_Length", block_name="x224Crq_and_RDP", length=1, inclusive=False,
                   fuzzable=False, endian=">")
        s_block_end("x224Crq_length")
        if (s_block_start("x224Crq_and_RDP")):
            if (s_block_start("x224Crq")):
                s_static("\xe0", name="PDU Type")  # connection request
                s_word(value=0x00, name="Destination reference")
                s_word(value=0x00, name="Source reference")
                s_static("\x0e", name="flags")
            s_block_end("x224Crq")
            if (s_block_start("RDP")):
                s_string("Cookie: mstshash=windows10", max_len=1441,
                         name="Routing Token/Cookie")  # with Routing Token/Cookie
                s_static("\x0d\x0a")
                s_static("\x06", name="Type")
                s_static("\x08", name="rdp_flags")
                s_static("\x24\x00", name="length")
                s_bit_field(value=0x01, width=128, name="correlationId")
                s_bit_field(value=0x00, width=128, name="reserved")
            s_block_end("RDP")
        s_block_end("x224Crq_and_RDP")
    s_block_end("request")

    # without Routing Token/Cookie (can't recognize )
    s_initialize("Client X.224 Connection Request PDU(rdpNegCorrelationInfo)2")
    if (s_block_start("request")):
        if (s_block_start("tpktHeader")):
            s_static("\x03", name="Version")
            s_static("\x00", name="Reserved")
            s_size(name="total_Length", block_name="request", length=2, inclusive=False, fuzzable=False, endian=">")
        s_block_end("tpktHeader")
        if (s_block_start("x224Crq_length")):
            s_size(name="x224Crq_and_RDP_Length", block_name="x224Crq_and_RDP", length=1, inclusive=False,
                   fuzzable=False, endian=">")
        s_block_end("x224Crq_length")
        if (s_block_start("x224Crq_and_RDP")):
            if (s_block_start("x224Crq")):
                s_static("\xe0", name="PDU Type")  # connection request
                s_word(value=0x00, name="Destination reference")
                s_word(value=0x00, name="Source reference")
                s_static("\x0e", name="flags")
            s_block_end("x224Crq")
            if (s_block_start("RDP")):
                s_static("\x06", name="Type")
                s_static("\x08", name="rdp_flags")
                s_static("\x24\x00", name="length")
                s_bit_field(value=0x01, width=128, name="correlationId")
                s_bit_field(value=0x00, width=128, name="reserved")
            s_block_end("RDP")
        s_block_end("x224Crq_and_RDP")
    s_block_end("request")

    # sess.connect(s_get("Client X.224 Connection Request PDU(rdpNegReq)1"))
    # sess.connect(s_get("Client X.224 Connection Request PDU(rdpNegReq)2"))
    # sess.connect(s_get("Client X.224 Connection Request PDU(rdpNegCorrelationInfo)1"))
    # can't recognize this
    # sess.connect(s_get("Client X.224 Connection Request PDU(rdpNegCorrelationInfo)2"))

    sess.connect(s_get("Client X.224 Connection Confirm PDU(RDP_NEG_RSP)"))
    sess.connect(s_get("Client X.224 Connection Confirm PDU(RDP_NEG_FAILURE)"))

    sess.connect(s_get("Client_MCC_Connection_Response_PDU"))

    sess.connect(s_get("Client_MCC_Connection_Request_PDU"))

    sess.connect(s_get("Server_MCS_Channel Join_Confirm_PDU"))

    sess.connect(s_get("RDP_Server_MCS_Attach_User_Confirm_PDU"))

    sess.connect(s_get("RDP_Client_MCS_Erect_Domain_Request_PDU"))

    sess.connect(s_get("RDP_Client_MCS_Channel_Join_Request_PDU"))

    sess.connect(s_get("RDP_Client_MCS_Attach_User_Request_PDU"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "172.16.145.56"
    start_cmds = []
    proc_name = ""
    pport = 3389
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
