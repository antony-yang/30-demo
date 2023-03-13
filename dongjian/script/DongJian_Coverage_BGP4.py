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
			"default": "100.100.0.2"
		},
		"start_cmds": {
			"ness": 0,
			"default": []
		}
	},
	"proto": "BGP4"
}

def reset_conn(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    target.close()
    target.open()


def pre_send_recv(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    target.recv(2048)


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    sess = Session(
        index_start=0,
        index_end=20,
        target=Target(
            connection=SocketConnection(host=target_ip, proto="tcp", port=pport),
        ),
        crash_threshold_request=200,
        crash_threshold_element=200,
        restart_sleep_time=1,
        receive_data_after_each_request=False,
        **kwargs
    )

    s_initialize("open")
    s_block("bgp_open")
    s_static(name="marker", value="\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff")
    s_size(block_name="bgp_open", name="length", inclusive=False, endian=">", length=2, fuzzable=False)
    # s_static(value="\x01", name="type")
    s_random(name="type", value='\x01', min_length=1, max_length=1, num_mutations=10)
    s_static(name="version", value="\x04")
    # s_bytes(name="my auth sys", value=b"\x00\x00", size=2)
    s_static("\x00\x64")
    s_bytes(name="hold time", value=b"\x00\xb4", size=2)
    # s_random(name="hold time", value="\x00\xb4", min_length=2, max_length=2, num_mutations=20)
    s_bytes(name="bgp identifier", value=b"\x64\x64\x00\x01", size=4)
    # s_random(name="bgp identifier", value="\x64\x64\x00\x01", min_length=4, max_length=4, num_mutations=10)
    # s_static(name="opt parm len", value="\x00")
    # s_block_end("bgp_open")
    s_size(block_name="opt para", name="opt para len", length=1, endian='>')
    s_block_end("bgp_open")
    with s_block(name="opt para"):
        s_byte(name="cap_1", value=0x02, endian='>')
        s_size(block_name="cap_1_value", name="cap_1_len", length=1, endian='>', fuzzable=False)
        with s_block(name="cap_1_value"):
            s_byte(name="me_cap", value=0x01, endian='>', fuzzable=False)
            s_size(block_name="me_cap_value", name="me_cap_len", length=1, endian='>')
            with s_block(name="me_cap_value"):
                s_dword(name="1", value=0x00010001, endian='>')

        s_byte(name="cap_2", value=0x02, endian='>')
        s_size(block_name="cap_2_value", name="cap_2_len", length=1, endian='>', fuzzable=False)
        with s_block(name="cap_2_value"):
            s_byte(name="rcc_cap", value=0x80, endian='>')
            s_static(name="rcc_cap_len", value="\x00")

        s_byte(name="cap_3", value=0x02, endian='>')
        s_size(block_name="cap_3_value", name="cap_3_len", length=1, endian='>', fuzzable=False)
        with s_block(name="cap_3_value"):
            s_byte(name="rr_cap", value=0x02, endian='>')
            s_static(name="rr_cap_len", value="\x00")

        s_byte(name="cap_4", value=0x02, endian='>')
        s_size(block_name="cap_4_value", name="cap_4_len", length=1, endian='>', fuzzable=False)
        with s_block(name="cap_4_value"):
            s_byte(name="4a_cap", value=0x41, endian='>')
            s_size(block_name="4a_cap_value", name="4a_cap_len", length=1, endian='>')
            with s_block(name="4a_cap_value"):
                s_dword(name="4", value=0x000000c8, endian='>')

        s_byte(name="cap_5", value=0x02, endian='>')
        s_size(block_name="cap_5_value", name="cap_5_len", length=1, endian='>', fuzzable=False)
        with s_block(name="cap_5_value"):
            s_byte(name="gr_cap", value=0x40, endian='>')
            s_size(block_name="gr_cap_value", name="gr_cap_len", length=1, endian='>')
            with s_block(name="gr_cap_value"):
                s_dword(name="5", value=0x00008078, endian='>')

    s_initialize("update")
    s_block("bgp_update")
    s_static(name="marker", value="\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff")
    s_size(block_name="bgp_update", name="length", inclusive=False, endian=">", length=2, fuzzable=False)
    # s_static(value="\x02", name="type")
    s_random(name="type", value='\x02', min_length=1, max_length=1, num_mutations=10)
    s_size(block_name="unfeasible_routes_length", name="rlength", length=2, endian=">", fuzzable=False, inclusive=False)
    if s_block("unfeasible_routes_length"):
        s_size(block_name="ip_prefix", name="ip_length", length=1, endian=">", fuzzable=False, inclusive=False, math=lambda x: x*8)
        s_block("ip_prefix")
        s_random(value="\x64\x64\x01\x00", min_length=1, max_length=4, num_mutations=10, name="prefix")
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
            # s_size(block_name="as_path_seg", endian=">", fuzzable=False, inclusive=False, length=1)
            s_block("as_path_seg")
            s_random(value="\x00\x64", min_length=2, max_length=64, step=2, num_mutations=100, name="as_numbers")
            s_block_end()
        s_block_end()

        s_static(name="attr.flag3", value="\x40") # \x40 \x80 \xc0 \xe0
        s_static(name="attr.type3", value="\x03")
        s_size(block_name="next_hop", endian=">", fuzzable=False, inclusive=False, length=1)
        s_block("next_hop")
        s_random(value="\x64\x64\x01\x00", min_length=4, max_length=4, num_mutations=100, name="nhop")
        s_block_end()
    s_block_end()
    if s_block("nlri"):
        s_size(block_name="ip_prefix2", name="ip_length2", length=1, endian=">", fuzzable=False, inclusive=False, math=lambda x: x*8)
        # s_static("\x16")
        s_block("ip_prefix2")
        s_random(value="\x64\x64\x01\x00", min_length=1, max_length=4, num_mutations=10000, name="prefix2")
        s_block_end()
    s_block_end()
    s_block_end("bgp_update")

    s_initialize("notification")
    s_block("bgp_notification")
    s_static(name="marker", value="\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff")
    s_size(block_name="bgp_notification", name="length", inclusive=False, endian=">", length=2, fuzzable=False)
    # s_static(value="\x03", name="type")
    s_random(name="type", value='\x03', min_length=1, max_length=1, num_mutations=10)
    # s_group(name="type", values=["\x03", "\x06", "\x80", "\x41"])
    # s_group(name="error code", values=["\x01", "\x02", "\x03", "\x04", "\x05", "\x06"])
    # s_byte(name="sub error code", value=0)
    s_group(name="error code", values=["\x01", "\x02", "\x03", "\x04", "\x05", "\x06"])
    with s_block(name="error message", group="error code"):
        s_random(name="data", value="\x01"*8, min_length=1, max_length=512, num_mutations=7)
    s_block_end("bgp_notification")

    s_initialize("refresh")
    s_block("bgp_refresh")
    s_static(name="marker", value="\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff\xff\xff"
                                  "\xff\xff\xff\xff")
    s_size(block_name="bgp_refresh", name="length", inclusive=False, endian=">", length=2, fuzzable=False)
    s_static(value="\x05", name="type")
    s_word(name="AFI", value=0x0001, endian='>')
    s_byte(name="Res", value=0x0, endian='>')
    s_byte(name="SAFI", value=0x01, endian='>')
    s_block_end("bgp_refresh")

    s_initialize("keep-alive")
    s_static(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x13\x04")

    sess.connect(s_get("open"))
    sess.connect(s_get("update"))
    sess.connect(s_get("notification"))
    sess.connect(s_get("refresh"))
    sess.connect(s_get("keep-alive"))
    sess.connect(s_get("open"), s_get("keep-alive"))
    sess.connect(s_get("open"), s_get("refresh"))
    sess.connect(s_get("open"), s_get("update"))
    sess.connect(s_get("open"), s_get("notification"))
    sess.connect(s_get("keep-alive"), s_get("update"))
    sess.connect(s_get("refresh"), s_get("update"))
    sess.connect(s_get("update"), s_get("notification"))

    sess.fuzz_single_node_by_path(["open"])
    sess.fuzz_single_node_by_path(["update"])
    sess.fuzz_single_node_by_path(["refresh"])
    sess.fuzz_single_node_by_path(["keep-alive", "update"])
    sess.fuzz_single_node_by_path(["open", "keep-alive", "update"])
    sess.fuzz_single_node_by_path(["refresh", "update"])
    sess.fuzz_single_node_by_path(["open", "refresh", "update"])
    sess.fuzz_single_node_by_path(["keep-alive", "update", "notification"])
    sess.fuzz_single_node_by_path(["open", "keep-alive", "update", "notification"])
    sess.fuzz_single_node_by_path(["update", "notification"])


if __name__ == "__main__":
    start_cmd = []
    proc_name = ""
    target_ip = "100.100.0.2"
    pport = 179
    dport = 26002
    fuzz(start_cmd, proc_name, target_ip, pport, dport, script_start=True)
