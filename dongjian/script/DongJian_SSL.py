from DongJian import *
import ssl
import socket

socket.setdefaulttimeout(8)
param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 443
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
	"proto": "SSL"
}
ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    session = Session(
        target=Target(
            connection=SocketConnection(
                host=target_ip,
                port=pport,
                proto="ssl",
                sslcontext=ctx,
            )
        ),
        **kwargs
    )
    s_initialize("Request")
    s_group("Method", ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE'])
    s_delim(" ")
    s_string("/", name="resource")
    s_static("\r\n\r\n")
    session.connect(s_get("Request"))
    session.fuzz()


if __name__ == "__main__":
    target_ip = "127.0.0.1"
    start_cmds = []
    proc_name = ""
    pport = 8443
    dport= 0
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
