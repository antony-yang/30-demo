#!/usr/bin/env python


from DongJian import *
import socket
import base64

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


"""quit method"""


def SendQuitCmd(target, fuzz_data_logger, session, sock):
    target.send(b"QUIT\r\n")
    pass


"""receive welcome"""


def RecvWelcome(target, fuzz_data_logger, session, sock):
    ret = target.recv()
    print(ret)
    pass


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    """
    This example is a very simple FTP fuzzer using a process monitor (procmon).
    It assumes that the procmon is already running. The script will connect to
    the procmon and tell the procmon to start the target application
    (see start_cmd).
    The ftpd.py in `start_cmd` is a simple FTP server using pyftpdlib. You can
    substitute any FTP server.
    """

    socket.setdefaulttimeout(8)
    session = Session(
        target=Target(
            connection=SocketConnection(target_ip, pport, proto="tcp"),
            # procmon=pedrpc.Client(target_ip, dport),
            # procmon_options={"start_commands": [start_cmds]},
        ),
        index_start=3000,
        pre_send_callbacks=[RecvWelcome],
        **kwargs
    )

    """ Define data model. """
    # User
    s_initialize("user")
    s_static("USER test\r\n")

    # Pass(Fuzz)
    s_initialize("pass")
    s_static("PASS ")
    s_static("123456")
    s_static("\r\n")

    # # Pass(No fuzz)
    # s_initialize("pass")
    # s_static("PASS 123456\r\n")

    # PASV mode
    s_initialize('pasv')
    s_static('PASV\r\n')

    # Quit
    s_initialize("quit")
    s_static("quit\r\n")

    # Help
    s_initialize("help")
    s_static("HELP ")
    s_string("")
    s_static("\r\n")

    # Acct
    s_initialize("acct")
    s_static("ACCT ")
    s_string("")
    s_static("\r\n")

    # CWD
    s_initialize("cwd")
    s_static("CWD ")
    s_string("")
    s_static("\r\n")

    # Cdup
    s_initialize("cdup")
    s_static("CDUP ")
    s_string("")
    s_static("\r\n")

    # Smnt
    s_initialize("smnt")
    s_static("SMNT ")
    s_string("")
    s_static("\r\n")

    # Rein
    s_initialize("rein")
    s_static("REIN ")
    s_string("")
    s_static("\r\n")

    # Type1
    s_initialize("type1")
    s_static("TYPE ")
    s_string("A", 1)
    s_group("validvalue", ["N", "T", "C"])
    s_static("\r\n")

    # Type2
    s_initialize("type2")
    s_static("TYPE ")
    s_string("E", 1)
    s_group("validvalue", ["N", "T", "C"])
    s_static("\r\n")

    # Type3
    s_initialize("type3")
    s_static("TYPE ")
    s_string("I", 1)
    s_group("validvalue", ["N", "T", "C"])
    s_static("\r\n")

    # Type4
    s_initialize("type4")
    s_static("TYPE ")
    s_string("L", 1)
    s_byte(0xff, LITTLE_ENDIAN, "binary", False)
    s_group("validvalue", ["N", "T", "C"])
    s_static("\r\n")

    # Stru
    s_initialize("stru")
    s_static("STRU ")
    s_string("I", 1)
    s_group("validvalue", ["F", "R", "P"])
    s_static("\r\n")

    # Mode
    s_initialize("mode")
    s_static("MODE ")
    s_string("I", 1)
    s_group("validvalue", ["S", "B", "C"])
    s_static("\r\n")

    # Retr
    s_initialize("retr")
    s_static("RETR ")
    s_string(" ")
    s_static("\r\n")

    # Stor
    s_initialize("stor")
    s_static("STOR ")
    s_string(" ")
    s_static("\r\n")

    # Stou
    s_initialize("stou")
    s_static("STOU ")
    s_string(" ")
    s_static("\r\n")

    # Appe
    s_initialize("appe")
    s_static("APPE ")
    s_string(" ")
    s_static("\r\n")

    # Allo
    s_initialize("allo")
    s_static("ALLO")
    s_string(" ")
    s_word(65535)
    s_string(" ")
    s_string("R")
    s_string(" ")
    s_word(65535)
    s_static("\r\n")

    # Rest
    s_initialize("rest")
    s_static("REST ")
    s_string(" ")
    s_static("\r\n")

    # Rnfr
    s_initialize("rnfr")
    s_static("RNFR ")
    s_string(" ")
    s_static("\r\n")

    # Rnto
    s_initialize("rnto")
    s_static("RNTO ")
    s_string(" ")
    s_static("\r\n")

    # Abor
    s_initialize("abor")
    s_static("ABOR ")
    s_string(" ")
    s_static("\r\n")

    # Dele
    s_initialize("dele")
    s_static("DELE ")
    s_string(" ")
    s_static("\r\n")

    # Rmd
    s_initialize("rmd")
    s_static("RMD ")
    s_string(" ")
    s_static("\r\n")

    # Mkd
    s_initialize("mkd")
    s_static("MKD ")
    s_string(" ")
    s_static("\r\n")

    # Pwd
    s_initialize("pwd")
    s_static("PWD ")
    s_string(" ")
    s_static("\r\n")

    # List
    s_initialize("list")
    s_static("LIST ")
    s_string(" ")
    s_static("\r\n")

    # Nlst
    s_initialize("nlst")
    s_static("NLST ")
    s_string(" ")
    s_static("\r\n")

    # Site
    s_initialize("site")
    s_static("SITE ")
    s_string(" ")
    s_static("\r\n")

    # Syst
    s_initialize("syst")
    s_static("SYST ")
    s_string(" ")
    s_static("\r\n")

    # Stat
    s_initialize("stat")
    s_static("STAT ")
    s_string(" ")
    s_static("\r\n")

    # Noop
    s_initialize("noop")
    s_static("NOOP ")
    s_string(" ")
    s_static("\r\n")

    # Host
    s_initialize("host")
    s_static("HOST ")
    s_string(" ")
    s_static("\r\n")

    # Auth
    s_initialize("auth")
    s_static("AUTH ")
    s_string(" ")
    s_static("\r\n")

    # Adat
    s_initialize("adat")
    s_static("ADAT ")
    s_string(" ")
    s_static("\r\n")

    # Port
    s_initialize("port")
    s_static("PORT ")
    s_group("validvalue", ["C", "S", "E", "P"])
    s_static("\r\n")

    # Pbsz
    s_initialize("pbsz")
    s_static("PBSZ ")
    s_string(" ")
    s_word(65535)
    s_static("\r\n")

    # Ccc
    s_initialize("ccc")
    s_static("CCC ")
    s_string(" ")
    s_static("\r\n")

    # Mic
    s_initialize("mic")
    s_static("MIC ")
    s_block_start("micblock", None, base64.b64encode)
    s_string(" ")
    s_block_end("micblock")
    s_static("\r\n")

    # Conf
    s_initialize("coof")
    s_static("CONF ")
    s_block_start("confblock", None, base64.b64encode)
    s_string("")
    s_block_end("confblock")
    s_static("\r\n")

    # Enc
    s_initialize("enc")
    s_static("ENC ")
    s_block_start("encblock", None, base64.b64encode)
    s_string("")
    s_block_end("encblock")
    s_static("\r\n")

    # Algs
    s_initialize("algs")
    s_static("ALGS ")
    s_string(" ")
    s_static("\r\n")

    # Eprt
    s_initialize("eprt")
    s_static("EPRT ")
    s_string("|", 1)
    s_block_start("IPaddress")
    s_byte(255, LITTLE_ENDIAN, "binary", False)
    s_string(".", 1)
    s_byte(255, LITTLE_ENDIAN, "binary", False)
    s_string(".", 1)
    s_byte(255, LITTLE_ENDIAN, "binary", False)
    s_string(".", 1)
    s_byte(255, LITTLE_ENDIAN, "binary", False)
    s_block_end()
    s_string("|", 1)
    s_word(65535)
    s_static("\r\n")

    # Epsv
    s_initialize("epsv")
    s_static("EPSV ")
    s_byte(255)
    s_static("\r\n")

    # Feat
    s_initialize("feat")
    s_static("FEAT ")
    s_string("")
    s_static("\r\n")

    # Opts
    s_initialize("opts")
    s_static("OPTS ")
    s_string("")
    s_static("\r\n")

    # Lang
    s_initialize("lang")
    s_static("LANG ")
    s_byte(255)
    s_static(" ")
    s_string("")
    s_static("-")
    s_string("")
    s_static("\r\n")

    # Lprt
    s_initialize("lprt")
    s_static("LPRT ")
    s_byte(255)
    s_static(",")
    s_byte(255)
    s_static(",")
    s_byte(255)
    s_static(",")
    s_byte(255)
    s_static(",")
    s_byte(255)
    s_static(",")
    s_byte(255)
    s_static(",")
    s_byte(255)
    s_static(",")
    s_byte(255)
    s_static(",")
    s_byte(255)
    s_static("\r\n")

    # Lpsv
    s_initialize("lpsv")
    s_static("LPSV ")
    s_string("")
    s_static("\r\n")

    # Mdtm
    s_initialize("mdtm")
    s_static("MDTM ")
    s_string("")
    s_static("\r\n")

    # Mlst
    s_initialize("mlst")
    s_static("MLST ")
    s_string("")
    s_static("\r\n")

    # Mlsd
    s_initialize("mlsd")
    s_static("MLSD ")
    s_string("")
    s_static("\r\n")

    # Size
    s_initialize("size")
    s_static("SIZE ")
    s_string("")
    s_static("\r\n")

    # Xrmd
    s_initialize("xrmd")
    s_static("XRMD ")
    s_string("")
    s_static("\r\n")

    # Xmkd
    s_initialize("xmkd")
    s_static("XMKD ")
    s_string("")
    s_static("\r\n")

    # Xpwd
    s_initialize("xpwd")
    s_static("XPWD ")
    s_string("")
    s_static("\r\n")

    # Xcwd
    s_initialize("xcwd")
    s_static("XCWD ")
    s_string("")
    s_static("\r\n")

    # Xcup
    s_initialize("xcup")
    s_static("XCUP ")
    s_string("")
    s_static("\r\n")

    cmds = ["help", "acct", "cwd", "cdup", "smnt", "rein", "type1", "type2",
            "type3", "type4", "stru", "mode", "retr", "stor", "stou", "appe",
            "allo", "rest", "rnfr", "rnto", "abor", "dele", "rmd", "mkd", "pwd",
            "list", "nlst", "site", "syst", "stat", "noop", "host", "auth", "adat",
            "port", "pbsz", "ccc", "mic", "coof", "enc", "algs", "eprt", "epsv",
            "feat", "opts", "lang", "lprt", "lpsv", "mdtm", "mlst", "mlsd", "size",
            "xrmd", "xmkd", "xpwd", "xcwd", "xcup"]

    for cmd in cmds:
        session.connect(s_get("user"))
        session.connect(s_get("user"), s_get("pass"))
        session.connect(s_get("pass"), s_get("pasv"))
        session.connect(s_get("pasv"), s_get(cmd))
        session.connect(s_get(cmd), s_get("quit"))

    """ grab the banner from the server """
    # session.pre_send = banner

    """ start fuzzing - define target and data """
    session.register_post_test_case_callback(SendQuitCmd)
    session.fuzz()


if __name__ == "__main__":
    target_ip = "172.16.145.25"
    start_cmds = ["C://CHKenFTP//CHKenFTP.exe"]
    proc_name = ""
    pport = 21
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)