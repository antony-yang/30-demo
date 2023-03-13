from DongJian import *
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
			"default": 1900
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
	"proto": "SSDP"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="udp"),
        ),
        **kwargs
    )

    s_initialize("Search")
    s_static("M-SEARCH * HTTP/1.1")
    s_static("HOST: 239.255.255.250:1900")
    s_static("MAN: \"ssdp:discover\"")
    s_static("MX: 5")
    s_string("ST: ssdp:all")

    s_initialize("Notify")
    s_static("M-SEARCH * HTTP/1.1")
    s_static("HOST: 239.255.255.250:1900")
    s_static("CACHE-CONTROL: max-age = seconds until advertisement expires")
    s_static("LOCATION: URL for UPnP description for root device")
    s_static("NT: search target")
    s_static("NTS: ssdp:alive")  #必须为ssdp:alive或者ssdp：byebye
    s_string("USN: advertisement UUID")


    sess.connect(s_get("Search"))
    sess.connect(s_get("Search"), s_get("Notify"))
    sess.fuzz()


if __name__ == "__main__":
    start_cmds = []
    target_ip = "127.0.0.1"
    pport = 1900
    dport = 26002
    proc_name = ""
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
