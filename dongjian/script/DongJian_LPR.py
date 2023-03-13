
from DongJian import *
param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 515
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
	"proto": "lpr"
}
def SendAbortCmd(target, fuzz_data_logger, session, sock):
    target.send(b"\x01\x0a")
    pass

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):


    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
        ),
        **kwargs
    )

    s_initialize(name="LPC")
    s_static("\x01")
    s_random("\x00", min_length=2, max_length=1458, num_mutations=10000)
    s_static("\x0a")

    s_initialize(name="LPR")
    s_static("\x02")
    s_random("\x00", min_length=2, max_length=1458, num_mutations=10000)
    s_static("\x0a")

    s_initialize(name="LPQ-short")
    s_static("\x03")
    s_random("\x00", min_length=2, max_length=729, num_mutations=5000)
    s_static("\x20")
    s_random("\x00", min_length=2, max_length=728, num_mutations=5000)
    s_static("\x0a")

    s_initialize(name="LPQ-long")
    s_static("\x04")
    s_random("\x00", min_length=2, max_length=729, num_mutations=5000)
    s_static("\x20")
    s_random("\x00", min_length=2, max_length=728, num_mutations=5000)
    s_static("\x0a")

    s_initialize(name="LPRM")
    s_static("\x05")
    s_random("\x00", min_length=2, max_length=729, num_mutations=5000)
    s_static("\x20")
    s_random("root", min_length=2, max_length=200, num_mutations=5000)
    s_static("\x20")
    s_random("\x00", min_length=2, max_length=527, num_mutations=5000)
    s_static("\x0a")

    s_initialize(name="sub-rcf")
    s_static("\x02")
    s_random("\x00", min_length=2, max_length=729, num_mutations=5000, name = "COUNT")
    s_static("\x20")
    s_random("\x00", min_length=2, max_length=728, num_mutations=5000, name = "NAME")
    s_static("\x0a")

    s_initialize(name="sub-rdf")
    s_static("\x03")
    s_random("\x00", min_length=2, max_length=729, num_mutations=5000, name = "COUNT")
    s_static("\x20")
    s_random("\x00", min_length=2, max_length=728, num_mutations=5000, name = "NAME")
    s_static("\x0a")

    # sess.connect(s_get("LPC"))
    # sess.connect(s_get("LPR"))
    # sess.connect(s_get("LPQ-short"))
    # sess.connect(s_get("LPQ-long"))
    # sess.connect(s_get("LPRM"))
    # sess.connect(s_get("LPR"))

    sess.connect(s_get("LPR"))
    sess.connect(s_get("LPR"), s_get("sub-rcf"))
    sess.connect(s_get("LPR"), s_get("sub-rdf"))

    sess.fuzz()


if __name__ == "__main__":
    target_ip = "10.38.4.25"
    start_cmds = []
    proc_name = ""
    pport = 515
    # pport = 80
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
