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
			"default": 123
		},
		"proc_name": {
			"ness": 1,
			"default": "ntpd"
		},
		"target_ip": {
			"ness": 1,
			"default": "127.0.0.1"
		},
		"start_cmds": {
			"ness": 1,
			"default": [
				"ntpd"
			]
		}
	},
	"proto": "NTP"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="udp"),
            # procmon=pedrpc.Client(target_ip, dport),
            # procmon_options={"start_commands": start_cmds, "proc_name": proc_name},
        ),
        **kwargs
    )
    s_initialize("NTP")
    s_bit_field(name="LI", width=2, value=3)
    s_bit_field(name="VN", width=3, value=4)
    s_bit_field(name="Mode", width=3, value=3)
    s_bit_field(name="Stratum", value=0x00, width=8)
    s_bit_field(name="Poll", width=8, value=0x03)
    s_bit_field(name="Precision", width=8, value=0xfa)
    s_bit_field(name="RootDelay", width=32, value=0x00000000)
    s_bit_field(name="RootDispersion", width=32, value=0x00000000)
    s_bit_field(name="ReferenceIdentifier", width=32, value=0x00000000)
    s_bit_field(name="ReferenceTimestamp", width=64, value=0x0000000000000000)
    s_bit_field(name="OriginateTimestamp", width=64, value=0x0000000000000000)
    s_bit_field(name="ReceiveTimestamp", width=64, value=0x0000000000000000)
    s_bit_field(name="TransmitTimestamp", width=64, value=0x0000000000000000)
    sess.connect(s_get("NTP"))
    sess.fuzz()


if __name__=="__main__":
    target_ip = "127.0.0.1"
    pport = 123
    dport = 26002
    start_cmds = []
    proc_name = "ntpd"
    start_cmds.append("ntpd")
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)