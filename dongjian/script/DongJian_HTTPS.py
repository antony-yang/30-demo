#!/usr/bin/env python
# Designed for use with boofuzz v0.0.9

from DongJian import *

import ssl

param = {
	"param": {
		"port": {
			"ness": 1,
			"default": 443
		},
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 443
		},
		"verify": {
			"ness": 1,
			"default": 0
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
		},
		"server_hostname": {
			"ness": 1,
			"default": "www.xxx.com"
		}
	},
	"proto": "HTTPS"
}

def get_ctx():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        server_hostname = kwargs["server_hostname"]
        verify = kwargs["verify"]
        port = kwargs["port"]
    except KeyError as e:
        print("lack of parameters")
        return

    if verify:
        session = Session(
            target=Target(
                connection=SocketConnection(
                    host=target_ip,
                    port=port,
                    proto="ssl",
                    server_hostname=server_hostname,
                ),
                # procmon=pedrpc.Client(target_ip, dport),
                # procmon_options={"start_commands": start_cmds},
            ),
        **kwargs
        )
    else:
        session = Session(
            target=Target(
                connection=SocketConnection(
                    host=target_ip,
                    port=pport,
                    proto="ssl",
                    #server_hostname=server_hostname,
                    sslcontext=get_ctx(),
                ),
                #procmon=pedrpc.Client(target_ip, dport),
                #procmon_options = {"start_commands": start_cmds},
            ),
        **kwargs
        )

    s_initialize(name="Request")
    with s_block(name="HTTPS", group="Method"):
        s_group("Method", ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE'])
        s_delim(" ", name='space-1')
        s_string("/index.html", name='Request-URI')
        s_delim(" ", name='space-2')
        s_string('HTTP/1.1', name='HTTP-Version')
        s_static("\r\n", name="Request-Line-CRLF")
    s_static("\r\n", "Request-CRLF")


    session.connect(s_get("Request"))
    session.fuzz()


if __name__ == "__main__":
    target_ip = "127.0.0.1"
    #target_ip = "10.1.0.93"
    start_cmds = []
    #start_cmds = ["/etc/init.d/nginx start"]
    proc_name = ""
    pport = 443
    dport = 26002
    port = 443
    server_hostname = "127.0.0.1"
    #server_hostname = "www.civdp.com"
    verify = False
    fuzz(start_cmds, proc_name, target_ip, pport, dport, scrip_start=True, server_hostname=server_hostname, verify=verify, port=port)