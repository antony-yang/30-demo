from DongJian import *
import uuid
import socket
import fcntl
import struct
socket.setdefaulttimeout(8)
param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 0,
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
			"default": [
			]
		},
        "net_interface": {
            "ness": 1,
            "default": "lo"
        }
	},
	"proto": "iec61850-goose"
}

def get_mac_addr(): #get mac address and trans it into hex byte format
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    print(mac)
    return transtomac(mac)

def transtomac(mac):
    sss = 0
    for s in range(0, 11, 2):
        ss = TransToInt(mac[s]) * 16 + TransToInt(mac[s+1])
        sss = sss*256 + ss
    mac2 = sss.to_bytes(6, byteorder="big", signed=False)
    return mac2

def TransToInt(c): #trans a char to a int
    if '0' <= c <= '9':
        return int(c)
    if 'a' <= c <= 'z':
        return ord(c) - ord('a') + 10
    return 0


def get_ip_addr(ifname): # get interface's ip address, parameter ifname only accept bytes(do not accept str class)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', ifname[:15])
    )[20:24]


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):
    try:
        kwargs["net_interface"]
    except KeyError as e:
        print("lack of parameter net_interface")
        return 0

    sess = Session(
        target=Target(
            connection=SocketConnection(host=kwargs["net_interface"], proto="raw-l2"),
        ),
        **kwargs
    )
    s_initialize("GOOSE")
    s_static(value="\xff\xff\xff\xff\xff\xff", name="dst")
    s_static(value=get_mac_addr(), name="src")
    s_static(value="\x81\x00", name="TPID")
    s_static(value="\x80\x42", name="TCI")
    s_static(value="\x88\xB8", name="Ethertype")
    s_block("PDU header")
    s_string(value="\x00\x33", name="APPID", max_len=2)
    s_static(value="\x00\x90", name="Length")
    s_static(value="\x00\x00", name="Reserved1")
    s_static(value="\x00\x00", name="Reserved2")
    s_block_end()
    s_block("APDU start")
    s_byte(0x61,"APDU start Tag")
    s_byte(0x81,"APDU start Length")
    s_byte(0x85,"APDU start Value")
    s_block_end()
    s_block("gocbRef String")
    s_byte(0x80, "gocbRef String Tag")
    s_byte(0x08, "gocbRef String Length")
    s_static(value="\x67\x6F\x63\x62\x52\x65\x66\x31", name="gocbRef String Value")
    s_block_end()
    s_block("TimeAllowedtoLive")
    s_byte(0x81, "TimeAllowedtoLive Tag")
    s_byte(0x05, "TimeAllowedtoLive Length")
    s_static(value="\x00\x00\x00\x27\x10", name="TimeAllowedtoLive Value")
    s_block_end()
    s_block("datSet String")
    s_byte(0x82, "datSet String Tag")
    s_byte(0x07, "datSet String Length")
    s_static(value="\x64\x61\x74\x53\x65\x74\x31", name="datSet String Value")
    s_block_end()
    s_block("goID String")
    s_byte(0x83, "goID String Tag")
    s_byte(0x05, "goID String Length")
    s_static(value="\x67\x6F\x49\x44\x31", name="goID String Value")
    s_block_end()
    s_block("t")
    s_byte(0x84, "t Tag")
    s_byte(0x08, "t Length")
    s_static(value="\x4E\xF2\x85\xE1\xF7\xCE\xD9\x00", name="t Value")
    s_block_end()
    s_block("stnum")
    s_byte(0x85, "stnum Tag")
    s_byte(0x05, "stnum Length")
    s_static(value="\x00\x00\x00\x00\x01", name="stnum Value")
    s_block_end()
    s_block("sqnum")
    s_byte(0x86, "sqnum Tag")
    s_byte(0x05, "sqnum Length")
    s_static(value="\x00\x00\x00\x00\x01", name="sqnum Value")
    s_block_end()
    s_block("test")
    s_byte(0x87, "test Tag")
    s_byte(0x01, "test Length")
    s_byte(0x00, "test Value")
    s_block_end()
    s_block("confRev")
    s_byte(0x88, "confRev Tag")
    s_byte(0x05, "confRev Length")
    s_static(value="\x00\x00\x00\x00\x01", name="confRev Value")
    s_block_end()
    s_block("ndsCom")
    s_byte(0x89, "ndsCom Tag")
    s_byte(0x01, "ndsCom Length")
    s_byte(0x00, "ndsCom Value")
    s_block_end()
    s_block("numDatSetEntries")
    s_byte(0x8A, "numDatSetEntries Tag")
    s_byte(0x05, "numDatSetEntries Length")
    s_static(value="\x00\x00\x00\x00\x09", name="numDatSetEntries Value")
    s_block_end()
    # s_block("allData")
    # s_byte(0xAB, "allData Tag")
    # s_byte(0x36, "allData Length")
    # s_string("", name="allData Value")
    # s_block_end()


    sess.connect(s_get("GOOSE"))
    sess.fuzz()


if __name__ == "__main__":
    target_ip = ""
    start_cmds = []
    proc_name = ""
    pport = 0
    dport=26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True, net_interface="ens33")