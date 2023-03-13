import struct

from DongJian import *
import socket
import fcntl
param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 58763
		},
		"src_ip": {
			"ness": 1,
			"default": "127.0.0.1"
		},
		"src_port": {
			"ness": 1,
			"default": 5060
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
	"proto": "SIP"
}

def get_ip_addr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def fuzz(start_cmds, proc_name, target_ip, pport, dport, taskname, tasktype, taskcreator, protocol, *args, **kwargs):
    try:
        kwargs["src_ip"]
        kwargs["src_port"]
    except KeyError as e:
        print("lack of parameter")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="udp"),
            #procmon=pedrpc.Client(target_ip, dport),
            #procmon_options={"start_commands": start_cmds, "proc_name": proc_name},
        ),
        **kwargs
    )
    s_initialize("SIP_invite")
    with s_block(name="invite"):
        invate = "INVITE sip:root@" + target_ip + ":" + str(pport) + " SIP/2.0"
        s_static(value=invate, name="Request-Line")
        s_static(value="\x0d\x0a")
        if s_block_start(name="Message_Header"):
            via = "Via: SIP/2.0/UDP " + kwargs["src_ip"] + ":" + str(kwargs["src_port"]) + ";rport;branch="
            s_static(value=via, name="Via")
            s_string(value="z9hG4bKPjea8233569b6741fd938234905f41f5de", name="branch", max_len=50)
            s_static(value="\x0d\x0a")
            s_static(value="Max-Forwards: ")
            s_string(value="70", name="Max-Forwards", size=2)
            s_static(value="\x0d\x0a")
            from_address = "From: <sip:user@" + kwargs["src_ip"] + ">;tag="
            s_static(value=from_address, name="From")
            s_string(value="d59ae6e0a4466a7031720a9266b57", name="tag", max_len=40)
            s_static(value="\x0d\x0a")
            to = "To: <sip:root@" + target_ip + ">"
            s_static(value=to, name="To")
            s_static(value="\x0d\x0a")
            contact = "Contact: <sip:user@" + kwargs["src_ip"] + ":" + str(kwargs["src_port"]) + ";ob>"
            s_static(value=contact, name="Contact")
            s_static(value="\x0d\x0a")
            call_id = "Call-ID: "
            s_static(value=call_id, name="Call-ID")
            s_string(value="caee92cc8b04b0e8ceada431a1defa1", max_len=40)
            s_static(value="\x0d\x0a")
            s_static(value="CSeq: ", name="CSeq")
            s_string("13907", max_len=10)
            s_static(value=" INVITE")
            s_static(value="\x0d\x0a")
            allow = "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS"
            s_static(value=allow, name="Allow")
            s_static(value="\x0d\x0a")
            supported = "Supported: replaces, 100rel, timer, norefersub"
            s_static(value=supported, name="Supported")
            s_static(value="\x0d\x0a")
            session = "Session-Expires: 1800"
            s_static(value=session, name="Session-Expires")
            s_static(value="\x0d\x0a")
            min_se = "Min-SE: 90"
            s_static(value=min_se, name="Min-SE")
            s_static(value="\x0d\x0a")
            user_agent = "User-Agent: MicroSIP/3.19.22"
            s_static(value=user_agent, name="User-Agent")
            s_static(value="\x0d\x0a")
            content_type = "Content-Type: application/sdp"
            s_static(value=content_type, name="Content-Type")
            s_static(value="\x0d\x0a")
            s_static(value="Content-Length: ", name="Content-Length")
            s_size(block_name="Message_Body", endian=">", output_format="", fuzzable=False)
            s_static(value="\x0d\x0a\x0d\x0a")
        s_block_end("Message_Header")
        if s_block_start("Message_Body"):
            s_static(value="\x76\x3d\x30", name="Session Description Protocol")
            s_static(value="\x0d\x0a")
            s_static(value="\x6f\x3d", name="o=")
            s_string("\x2d", name="Ownwe Username", size=1)
            s_static("\x20")
            s_string("\x33\x37\x38\x35\x36\x35\x30\x35\x32\x31", name="Session ID", max_len=20)
            s_static("\x20")
            s_string("\x33\x37\x38\x35\x36\x35\x30\x35\x32\x31", name="Session Version", max_len=20)
            s_static("\x20")
            s_static(value="\x49\x4e", name="Owner Network Type1")
            s_static("\x20")
            s_static(value="\x49\x50\x34", name="Owner Network Type2")
            s_static("\x20")
            s_static(value=kwargs["src_ip"], name="Owner Address")
            s_static(value="\x0d\x0a")
            s_static(value="s=")
            s_string("pjmedia", name="Session Name", size=7)
            s_static(value="\x0d\x0a")
            s_static(value="b=AS:84", name="Bandwidth Information1")
            s_static(value="\x0d\x0a")
            s_static("t=", name="Time Description")
            s_string("0", size=1)
            s_static(" ")
            s_string("0", size=1)
            s_static(value="\x0d\x0a")
            s_static(value="a=X-nat:", name="Session Attribute")
            s_string("0", size=1)
            s_static(value="\x0d\x0a")
            s_static(value="m=audio 4016 RTP/AVP 8 0 101", name="Media Description")
            s_static(value="\x0d\x0a")
            s_static(value="c=IN IP4 " + kwargs["src_ip"], name="Connection Information")
            s_static(value="\x0d\x0a")
            s_static(value="b=TIAS:")
            s_string("64000", name="Bandwidth Information2", size=5)
            s_static(value="\x0d\x0a")
            s_static(value="a=rtcp:4017 IN IP4 " + kwargs["src_ip"], name="Media Attribute1")
            s_static(value="\x0d\x0a")
            s_static(value="a=sendrecv", name="Media Attribute2")
            s_static(value="\x0d\x0a")
            s_static(value="a=rtpmap:8 PCMA/", name="Media Attribute3")
            s_string(value="8000", name="Media3_value", max_len=10)
            s_static(value="\x0d\x0a")
            s_static(value="a=rtpmap:0 PCMA/", name="Media Attribute4")
            s_string(value="8000", name="Media4_value", max_len=10)
            s_static(value="\x0d\x0a")
            s_static(value="a=rtpmap:101 telephone-event/", name="Media Attribute5")
            s_string(value="8000", name="Media5_value", max_len=10)
            s_static(value="\x0d\x0a")
            s_static(value="a=fmtp:101 0-16", name="Media Attribute")
            s_static(value="\x0d\x0a")
            s_static(value="a=ssrc:", name="Media Attribute6_1")
            s_string(value="199170201", max_len=15)
            s_static(value=" cname:", name="Media Attribute6_2")
            s_string(value="76f25b4670a7449c", max_len=20)
            s_static(value="\x0d\x0a")
        s_block_end("Message_Body")

    s_initialize("SIP_cancel")
    with s_block(name="cancel"):
        cancel = "CANCEL sip:root@" + target_ip + ":" + str(pport) + " SIP/2.0"
        s_static(value=cancel, name="Request-Line")
        s_static(value="\x0d\x0a")
        if s_block_start(name="Message_Header"):
            via = "Via: SIP/2.0/UDP " + kwargs["src_ip"] + ":" + str(kwargs["src_port"]) + ";rport;branch="
            s_static(value=via, name="Via")
            s_string(value="z9hG4bKPjea8233569b6741fd938234905f41f5de", name="branch", max_len=50)
            s_static(value="\x0d\x0a")
            s_static(value="Max-Forwards: ")
            s_string(value="70", name="Max-Forwards", size=2)
            s_static(value="\x0d\x0a")
            from_address = "From: <sip:user@" + kwargs["src_ip"] + ">;tag="
            s_static(value=from_address, name="From")
            s_string(value="d59ae6e0a4466a7031720a9266b57", name="tag", max_len=40)
            s_static(value="\x0d\x0a")
            to = "To: <sip:root@" + target_ip + ">"
            s_static(value=to, name="To")
            s_static(value="\x0d\x0a")
            call_id = "Call-ID: "
            s_static(value=call_id, name="Call-ID")
            s_string(value="caee92cc8b04b0e8ceada431a1defa1", max_len=40)
            s_static(value="\x0d\x0a")
            s_static(value="CSeq: ", name="CSeq")
            s_string("3751", max_len=10)
            s_static(value=" CANCEL")
            s_static(value="\x0d\x0a")
            user_agent = "User-Agent: MicroSIP/3.19.22"
            s_static(value=user_agent, name="User-Agent")
            s_static(value="\x0d\x0a")
            s_static(value="Content-Length: 0", name="Content-Length")
            s_static(value="\x0d\x0a\x0d\x0a")
        s_block_end("Message_Header")

    s_initialize("SIP_ack")
    with s_block(name="ack"):
        cancel = "ACK sip:root@" + target_ip + ":" + str(pport) + " SIP/2.0"
        s_static(value=cancel, name="Request-Line")
        s_static(value="\x0d\x0a")
        if s_block_start(name="Message_Header"):
            via = "Via: SIP/2.0/UDP " + kwargs["src_ip"] + ":" + str(kwargs["src_port"]) + ";rport;branch="
            s_static(value=via, name="Via")
            s_string(value="z9hG4bKPjea8233569b6741fd938234905f41f5de", name="branch", max_len=50)
            s_static(value="\x0d\x0a")
            s_static(value="Max-Forwards: ")
            s_string(value="70", name="Max-Forwards", size=2)
            s_static(value="\x0d\x0a")
            from_address = "From: <sip:user@" + kwargs["src_ip"] + ">;tag="
            s_static(value=from_address, name="From")
            s_string(value="d59ae6e0a4466a7031720a9266b57", name="tag", max_len=40)
            s_static(value="\x0d\x0a")
            to = "To: <sip:root@" + target_ip + ">"
            s_static(value=to, name="To")
            s_static(value="\x0d\x0a")
            call_id = "Call-ID: "
            s_static(value=call_id, name="Call-ID")
            s_string(value="caee92cc8b04b0e8ceada431a1defa1", max_len=40)
            s_static(value="\x0d\x0a")
            s_static(value="CSeq: ", name="CSeq")
            s_string("13907", max_len=10)
            s_static(value=" ACK")
            s_static(value="\x0d\x0a")
            s_static(value="Content-Length: 0", name="Content-Length")
            s_static(value="\x0d\x0a\x0d\x0a")
        s_block_end("Message_Header")

    s_initialize("SIP_trying")
    with s_block(name="trying"):
        cancel = "SIP/2.0 100 Trying"
        s_static(value=cancel, name="Request-Line")
        s_static(value="\x0d\x0a")
        if s_block_start(name="Message_Header"):
            via = "Via: SIP/2.0/UDP " + kwargs["src_ip"] + ":" + str(kwargs["src_port"]) + ";rport;branch="
            s_static(value=via, name="Via")
            s_string(value="z9hG4bKPjea8233569b6741fd938234905f41f5de", name="branch", max_len=50)
            s_static(value="\x0d\x0a")
            s_static(value="Max-Forwards: ")
            s_string(value="70", name="Max-Forwards", size=2)
            s_static(value="\x0d\x0a")
            from_address = "From: <sip:user@" + kwargs["src_ip"] + ">;tag="
            s_static(value=from_address, name="From")
            s_string(value="d59ae6e0a4466a7031720a9266b57", name="tag", max_len=40)
            s_static(value="\x0d\x0a")
            to = "To: <sip:root@" + target_ip + ">"
            s_static(value=to, name="To")
            s_static(value="\x0d\x0a")
            call_id = "Call-ID: "
            s_static(value=call_id, name="Call-ID")
            s_string(value="caee92cc8b04b0e8ceada431a1defa1", max_len=40)
            s_static(value="\x0d\x0a")
            s_static(value="CSeq: ", name="CSeq")
            s_string("3751", max_len=10)
            s_static(value=" INVITE")
            s_static(value="\x0d\x0a")
            s_static(value="Content-Length: 0", name="Content-Length")
            s_static(value="\x0d\x0a\x0d\x0a")
        s_block_end("Message_Header")

    s_initialize("SIP_ringing")
    with s_block(name="ringing"):
        cancel = "SIP/2.0 180 Ringing"
        s_static(value=cancel, name="Request-Line")
        s_static(value="\x0d\x0a")
        if s_block_start(name="Message_Header"):
            via = "Via: SIP/2.0/UDP " + kwargs["src_ip"] + ":" + str(kwargs["src_port"]) + ";rport;branch="
            s_static(value=via, name="Via")
            s_string(value="z9hG4bKPjea8233569b6741fd938234905f41f5de", name="branch", max_len=50)
            s_static(value="\x0d\x0a")
            call_id = "Call-ID: "
            s_static(value=call_id, name="Call-ID")
            s_string(value="caee92cc8b04b0e8ceada431a1defa1", max_len=40)
            s_static(value="\x0d\x0a")
            from_address = "From: <sip:user@" + kwargs["src_ip"] + ">;tag="
            s_static(value=from_address, name="From")
            s_string(value="d59ae6e0a4466a7031720a9266b57", name="tag", max_len=40)
            s_static(value="\x0d\x0a")
            to = "To: <sip:root@" + target_ip + ">"
            s_static(value=to, name="To")
            s_static(value="\x0d\x0a")
            s_static(value="CSeq: ", name="CSeq")
            s_string("3751", max_len=10)
            s_static(value=" INVITE")
            s_static(value="\x0d\x0a")
            contact = "Contact: <sip:user@" + kwargs["src_ip"] + ":" + str(kwargs["src_port"]) + ";ob>"
            s_static(value=contact, name="Contact")
            s_static(value="\x0d\x0a")
            allow = "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS"
            s_static(value=allow, name="Allow")
            s_static(value="\x0d\x0a")
            s_static(value="Content-Length: 0", name="Content-Length")
            s_static(value="\x0d\x0a\x0d\x0a")
        s_block_end("Message_Header")

    s_initialize("SIP_busy")
    with s_block(name="busy"):
        cancel = "SIP/2.0 486 Buzy Here"
        s_static(value=cancel, name="Request-Line")
        s_static(value="\x0d\x0a")
        if s_block_start(name="Message_Header"):
            via = "Via: SIP/2.0/UDP " + kwargs["src_ip"] + ":" + str(kwargs["src_port"]) + ";rport;branch="
            s_static(value=via, name="Via")
            s_string(value="z9hG4bKPjea8233569b6741fd938234905f41f5de", name="branch", max_len=50)
            s_static(value="\x0d\x0a")
            call_id = "Call-ID: "
            s_static(value=call_id, name="Call-ID")
            s_string(value="caee92cc8b04b0e8ceada431a1defa1", max_len=40)
            s_static(value="\x0d\x0a")
            from_address = "From: <sip:user@" + kwargs["src_ip"] + ">;tag="
            s_static(value=from_address, name="From")
            s_string(value="d59ae6e0a4466a7031720a9266b57", name="tag", max_len=40)
            s_static(value="\x0d\x0a")
            to = "To: <sip:root@" + target_ip + ">"
            s_static(value=to, name="To")
            s_static(value="\x0d\x0a")
            s_static(value="CSeq: ", name="CSeq")
            s_string("3751", max_len=10)
            s_static(value=" INVITE")
            s_static(value="\x0d\x0a")
            allow = "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS"
            s_static(value=allow, name="Allow")
            s_static(value="\x0d\x0a")
            s_static(value="Content-Length: 0", name="Content-Length")
            s_static(value="\x0d\x0a\x0d\x0a")
        s_block_end("Message_Header")

    s_initialize("SIP_bye")
    with s_block(name="bye"):
        cancel = "BYE sip:root@" + target_ip + ":" + str(pport) + " SIP/2.0"
        s_static(value=cancel, name="Request-Line")
        s_static(value="\x0d\x0a")
        if s_block_start(name="Message_Header"):
            via = "Via: SIP/2.0/UDP " + kwargs["src_ip"] + ":" + str(kwargs["src_port"]) + ";rport;branch="
            s_static(value=via, name="Via")
            s_string(value="z9hG4bKPjea8233569b6741fd938234905f41f5de", name="branch", max_len=50)
            s_static(value="\x0d\x0a")
            s_static(value="Max-Forwards: ")
            s_string(value="70", name="Max-Forwards", size=2)
            s_static(value="\x0d\x0a")
            from_address = "From: <sip:user@" + kwargs["src_ip"] + ">;tag="
            s_static(value=from_address, name="From")
            s_string(value="d59ae6e0a4466a7031720a9266b57", name="tag", max_len=40)
            s_static(value="\x0d\x0a")
            to = "To: <sip:root@" + target_ip + ">"
            s_static(value=to, name="To")
            s_static(value="\x0d\x0a")
            call_id = "Call-ID: "
            s_static(value=call_id, name="Call-ID")
            s_string(value="caee92cc8b04b0e8ceada431a1defa1", max_len=40)
            s_static(value="\x0d\x0a")
            s_static(value="CSeq: ", name="CSeq")
            s_string("13907", max_len=10)
            s_static(value=" BYE")
            s_static(value="\x0d\x0a")
            user_agent = "User-Agent: MicroSIP/3.19.22"
            s_static(value=user_agent, name="User-Agent")
            s_static(value="\x0d\x0a")
            s_static(value="Content-Length: 0", name="Content-Length")
            s_static(value="\x0d\x0a\x0d\x0a")
        s_block_end("Message_Header")

    sess.connect(s_get("SIP_invite"))
    sess.connect(s_get("SIP_cancel"))
    sess.connect(s_get("SIP_ack"))
    sess.connect(s_get("SIP_trying"))
    sess.connect(s_get("SIP_ringing"))
    sess.connect(s_get("SIP_bye"))
    sess.fuzz()


if __name__ == "__main__":
    start_cmds = []
    #start_cmds = ["C:\\Users\\Administrator\\AppData\\Local\\MicroSIP\\microsip.exe"]
    proc_name = ""
    target_ip = "127.0.0.1"
    net_interface = "ens33"
    src_ip = get_ip_addr(bytes(net_interface, encoding="utf-8"))
    src_port = "5060"
    pport = 58763
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, src_ip=src_ip, src_port=src_port)
