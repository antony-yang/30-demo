from DongJian import *
import socket

param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 179
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
	"proto": "BGP4"
}

def KeepAlive(target_ip, pport):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target_ip, pport))
    sock.send(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x13\x04")

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, proto="tcp", port=pport),
            #procmon=pedrpc.Client(target_ip, dport),
            #procmon_options={"start_commands": start_cmds, "proc_name": proc_name},
        ),
        **kwargs
    )

    s_initialize("open")
    s_block("bgp_open")
    s_static(name="marker", value="\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff")
    s_size(block_name="bgp_open", name="length", inclusive=False, endian=">", length=2, fuzzable=False)
    s_static(value="\x01", name="type")
    s_static(name="version", value="\x04")
    s_bytes(name="my auth sys", value=b"\x00\x00", size=2)
    s_bytes(name="hold time", value=b"\x00\xb4", size=2)
    s_bytes(name="bgp identifier", value=b"\x64\x64\x00\x01", size=4)
    s_static(name="opt parm len", value="\x00")
    s_block_end("bgp_open")

    s_initialize("update")
    s_block("bgp_update")
    s_static(name="marker", value="\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff")
    s_size(block_name="bgp_update", name="length", inclusive=False, endian=">", length=2, fuzzable=False)
    s_static(value="\x02", name="type")
    s_size(block_name="unfeasible_routes_length", name="rlength", length=2, endian=">", fuzzable=False, inclusive=False)
    if s_block("unfeasible_routes_length"):
        s_size(block_name="ip_prefix", name="ip_length", length=1, endian=">", fuzzable=False,
               inclusive=False, math=lambda x: x*8)
        s_block("ip_prefix")
        s_random(value="\x0a"*4, min_length=1, max_length=4, num_mutations=10000, name="prefix")
        s_block_end()
    s_block_end()
    s_size(block_name="total_path_attr_path", name="plength", length=2, endian=">", fuzzable=False, inclusive=False)
    if s_block("total_path_attr_path"):

        s_static(name="attr.flag1", value="\x40") # \x40 \x80 \xc0 \xe0
        s_static(name="attr.type1", value="\x01")
        s_size(block_name="origin", endian=">", fuzzable=False, inclusive=False, length=1)
        s_block("origin")
        s_group(values=["\x00", "\x01", "\x02"], name="origin_type")
        s_block_end()

        s_static(name="attr.flag2", value="\x40") # \x40 \x80 \xc0 \xe0
        s_static(name="attr.type2", value="\x02")
        s_size(block_name="as_path", endian=">", fuzzable=False, inclusive=False, length=1)
        if s_block("as_path"):
            s_group(values=["\x01", "\x02"], name="as_type")
            s_size(block_name="as_path_seg", endian=">", fuzzable=False, inclusive=False, length=1, math=lambda x: int(x/2))
            s_block("as_path_seg")
            s_random(value="\x0a" * 2, min_length=2, max_length=64, step=2, num_mutations=10000, name="as_numbers")
            s_block_end()
        s_block_end()

        s_static(name="attr.flag3", value="\x40") # \x40 \x80 \xc0 \xe0
        s_static(name="attr.type3", value="\x03")
        s_size(block_name="next_hop", endian=">", fuzzable=False, inclusive=False, length=1)
        s_block("next_hop")
        s_random(value="\x0a"*4, min_length=4, max_length=4, num_mutations=10000, name="nhop")
        s_block_end()
    s_block_end()
    if s_block("nlri"):
        s_size(block_name="ip_prefix2", name="ip_length2", length=1, endian=">", fuzzable=False, inclusive=False,
               math=lambda x: x*8)
        s_block("ip_prefix2")
        s_random(value="\x0a"*4, min_length=1, max_length=4, num_mutations=10000, name="prefix2")
        s_block_end()
    s_block_end()
    s_block_end("bgp_update")

    s_initialize("notification")
    s_block("bgp_notification")
    s_static(name="marker", value="\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff")
    s_size(block_name="bgp_notification", name="length", inclusive=False, endian=">", length=2, fuzzable=False)
    s_static(value="\x03", name="type")
    s_group(name="error code", values=["\x01", "\x02", "\x03", "\x04", "\x05", "\x06"])
    s_byte(name="sub error code", value=0)
    s_random(name="data", value="\x00"*8, min_length=0, max_length=256, num_mutations=10000)
    s_block_end("bgp_notification")

    s_initialize("refresh")
    s_block("bgp_refresh")
    s_static(name="marker", value="\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff")
    s_size(block_name="bgp_open", name="length", inclusive=False, endian=">", length=2, fuzzable=False)
    s_static(value="\x05", name="type")
    s_block_end("bgp_refresh")

    sess.connect(s_get("open"))
    sess.connect(s_get("open"), s_get("update"))
    sess.connect(s_get("update"), s_get("notification"))
    sess.fuzz()


if __name__ == "__main__":
    start_cmd = ["bgpd"]
    proc_name = ""
    target_ip = "100.100.0.2"
    pport = 179
    dport = 26002
    fuzz(start_cmd, proc_name, target_ip, pport, dport, script_start=True)
    #KeepAlive(target_ip,pport)
