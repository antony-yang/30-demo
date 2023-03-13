#!/usr/bin/env python
from DongJian import *
# import pykd
import socket
from DongJian import pgraph
import time
import ssl
import threading


socket.setdefaulttimeout(10)

param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 21
		},
		"proc_name": {
			"ness": 0,
			"default": ""
		},
		"target_ip": {
			"ness": 1,
			"default": "10.38.4.16"
		},
		"start_cmds": {
			"ness": 1,
			"default": [
				"C:\\CHKenFTP\\CHKenFTP.exe"
			]
		}
	},
	"proto": "FTP"
}

def banner(sock):
    sock.recv(1024)


def post_send(target, fuzz_data_logger, session, sock):
    time.sleep(1)
    target.send(b"quit\r\n")


def pre_send(target, fuzz_data_logger, session, sock):
    ret = target.recv()
    if session.num_fuzzed == 0:
        target.send(b"auth tls\r\n")
        ret = target.recv()
        while len(ret) == 0:
            ret = target.recv()
        time.sleep(1)
        target._target_connection._sock = ssl.SSLContext(ssl.PROTOCOL_SSLv23).wrap_socket(target._target_connection._sock)

def btw(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    ret = str(session.last_recv, encoding="utf-8")
    ret = ret.split("(")[1]
    ret = ret.split(")")[0]
    ret = ret.split(",")
    ip = ret[0]+"."+ret[1]+"."+ret[2]+"."+ret[3]
    port = int(ret[4]) * 256 + int(ret[5])
    print(ip + ":" + str(port))
    time.sleep(1)
    t = threading.Thread(target=sock_thread, args=(ip, port, ))
    t.start()

def sock_thread(ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    sock.settimeout(2)
    try:
        res = sock.recv(4096)
        print(res)
        sock.close()
    except Exception as e:
        print(e)
        sock.close()


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        index_start=0,
        index_end=20,
        target=Target(
            connection=SocketConnection(target_ip, pport, proto="tcp"),
        ),
        pre_send_callbacks=[pre_send],
        sleep_time=0.1,
        **kwargs
    )


    """ Define data model. """
    # User
    s_initialize("user")
    s_static("USER aaa\r\n")

    # Pass(Fuzz)
    s_initialize("pass")
    s_static("PASS ")
    s_static("123456")
    s_static("\r\n")

    s_initialize("padding")
    s_static("pasv")
    s_static("\r\n")

    cmds = [
            "TYPE1 ", "HELP ", "CWD ", "CDUP ", "SMNT ", "NOOP ", "STRU ", "MODE "
            ]
    cmds2 = [
            "STOR ", "RETR "
            ]

    s_initialize("sample" + str(0))
    s_static(cmds[0])
    s_string("A", 1)
    s_group("validvalue", ["N", "T", "C"])
    s_static("\r\n")

    for j in range(1, 8):
        s_initialize("sample" + str(j))
        s_static(cmds[j])
        s_string("")
        s_static("\r\n")

    for y in range(8, 10):
        s_initialize("sample" + str(y))
        s_static(cmds2[y - 8])
        s_string("")
        s_static("\r\n")

    sess.register_post_test_case_callback(post_send)

    for h in range(0, 8):
        sess.connect(s_get("user"))
        sess.connect(s_get("user"), s_get("pass"))
        sess.connect(s_get("pass"), s_get("sample" + str(h)))

    for x in range(8, 10):
        sess.connect(s_get("user"))
        sess.connect(s_get("user"), s_get("pass"))
        sess.connect(s_get("pass"), s_get("padding"))
        sess.connect(s_get("padding"), s_get("sample" + str(x)), callback=btw)

    for k in range(0, 8):
        sess.fuzz_single_node_by_path(["user", "pass", "sample"+str(k)])

    for p in range(8, 10):
        sess.fuzz_single_node_by_path(["user", "pass", "padding", "sample" + str(p)])


if __name__ == "__main__":
    target_ip = "10.38.4.112"
    start_cmds = []
    proc_name = ""
    pport = 21
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
