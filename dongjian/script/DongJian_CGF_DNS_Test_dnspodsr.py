#!/usr/bin/python

import binascii

from DongJian import *


param = {
    "param":
        {
        "pport": {"ness": 1, "default": 53},
        "target_ip": {"ness": 1, "default": "127.0.0.1"},
        "cov_ip": {"ness": 0, "default":"127.0.0.1"},
        "cov_port": {"ness": 0, "default":9999},
        "path" : {"ness":1, "default":"/home/dongjian/dns/dnspod-afl-test/src/"},
        "target":{"ness":1, "default":"dnspod-sr"},
        "params":{"ness":1, "default":[]}
        },
        "proto": "dns"
    }

def insert_questions(target, fuzz_data_logger, session, node, edge):
    node.names['Questions'].value = 1 + node.names['queries'].current_reps
    node.names['Authority'].value = 1 + node.names['auth_nameservers'].current_reps


def to_ascii(h):
    list_s = []
    for i in range(0, len(h), 2):
        list_s.append(chr(int(h[i:i+2], 16)))
    return ''.join(list_s)


def genContent(url):
    url = str(url).strip("'b").strip("'")
    colarr = str(url).split(".")
    reurl = ""
    for col in colarr:
        size = len(col)
        hexstr = hex(size)[2:]
        num = to_ascii(hexstr)
        reurl += num + col
    reurl += to_ascii('0')
    return reurl


# "/home/dongjian/dns/dnspod-afl-test/src/"
# "dnspod-sr"

def fuzz(target_ip, pport, path, target, params,  *args, **kwargs):

    sess = CovSession(
        target=Target(
            connection=SocketConnection(target_ip, pport, proto="udp"),
        ),
        receive_data_after_each_request=False,
        receive_data_after_fuzz=False,
        enable_cov_mode=True,
        **kwargs
    )

    #A
    s_initialize("A")
    s_word(65535, name="TransactionID", fuzzable=True, full_range=True)
    s_word(256, name="Flags", endian='>', full_range=True)
    s_word(1, name="Questions", endian='>', full_range=True)
    s_word(0, name="Answer", endian='>', full_range=True)
    s_word(0, name="Authority", endian='>', full_range=True)
    s_word(0, name="Additional", endian='>', full_range=True)
    s_block_start("content", None, genContent)
    s_string("www.baidu.com")
    s_block_end("content")
    s_word(1, name="type", endian='>', full_range=True)
    s_word(1, name="class", endian='>', full_range=True)

    #AAAA
    s_initialize("AAAA")
    s_word(65535, name="TransactionID", fuzzable=True)
    s_word(256, name="Flags", endian='>')
    s_word(1, name="Questions", endian='>')
    s_word(0, name="Answer", endian='>')
    s_word(0, name="Authority", endian='>')
    s_word(0, name="Additional", endian='>')
    s_block_start("content", None, genContent)
    s_string("nti.nsfocus.com")
    s_block_end("content")
    s_word(28, name="type", endian='>')
    s_word(1, name="class", endian='>')

    #NS
    s_initialize("NS")
    s_word(65535, name="TransactionID",fuzzable=True)
    s_word(256, name="Flags", endian='>')
    s_word(1, name="Questions", endian='>')
    s_word(0, name="Answer", endian='>')
    s_word(0, name="Authority", endian='>')
    s_word(0, name="Additional", endian='>')
    s_block_start("content", None, genContent)
    s_string("www.163.com")
    s_block_end("content")
    s_word(2, name="type", endian='>')
    s_word(1, name="class", endian='>')

    #CNAME
    s_initialize("CNAME")
    s_word(65535, name="TransactionID",fuzzable=True)
    s_word(256, name="Flags", endian='>')
    s_word(1, name="Questions", endian='>')
    s_word(0, name="Answer", endian='>')
    s_word(0, name="Authority", endian='>')
    s_word(0, name="Additional", endian='>')
    s_block_start("content", None, genContent)
    s_string("www.qq.com")
    s_block_end("content")
    s_word(5, name="type", endian='>')
    s_word(1, name="class", endian='>')

    #MX
    s_initialize("MX")
    s_word(65535, name="TransactionID",fuzzable=True)
    s_word(256, name="Flags", endian='>')
    s_word(1, name="Questions", endian='>')
    s_word(0, name="Answer", endian='>')
    s_word(0, name="Authority", endian='>')
    s_word(0, name="Additional", endian='>')
    s_block_start("content", None, genContent)
    s_string("civdp.com")
    s_block_end("content")
    s_word(15, name="type", endian='>')
    s_word(1, name="class", endian='>')


    #PTR
    s_initialize("PTR")
    s_word(65535, name="TransactionID",fuzzable=True)
    s_word(256, name="Flags", endian='>')
    s_word(1, name="Questions", endian='>')
    s_word(0, name="Answer", endian='>')
    s_word(0, name="Authority", endian='>')
    s_word(0, name="Additional", endian='>')
    s_block_start("content", None, genContent)
    s_string("8.8.8.8.in-addr.arpa")
    s_block_end("content")
    s_word(12, name="type", endian='>')
    s_word(1, name="class", endian='>')

    #TXT
    s_initialize("TXT")
    s_word(65535, name="TransactionID",fuzzable=True)
    s_word(256, name="Flags", endian='>')
    s_word(1, name="Questions", endian='>')
    s_word(0, name="Answer", endian='>')
    s_word(0, name="Authority", endian='>')
    s_word(0, name="Additional", endian='>')
    s_block_start("content", None, genContent)
    s_string("txt.baidu.com")
    s_block_end("content")
    s_word(16, name="type", endian='>')
    s_word(1, name="class", endian='>')

    #SRV
    s_initialize("SRV")
    s_word(65535, name="TransactionID", fuzzable=True)
    s_word(256, name="Flags", endian='>')
    s_word(1, name="Questions", endian='>')
    s_word(0, name="Answer", endian='>')
    s_word(0, name="Authority", endian='>')
    s_word(0, name="Additional", endian='>')
    s_block_start("content", None, genContent)
    s_string("_xmpp-server._tcp.aischang.com")
    s_block_end("content")
    s_word(33, name="type", endian='>')
    s_word(1, name="class", endian='>')

    #SOA
    s_initialize("SOA")
    s_word(65535, name="TransactionID", fuzzable=True)
    s_word(256, name="Flags", endian='>')
    s_word(1, name="Questions", endian='>')
    s_word(0, name="Answer", endian='>')
    s_word(0, name="Authority", endian='>')
    s_word(0, name="Additional", endian='>')
    s_block_start("content", None, genContent)
    s_string("www.baidu.com")
    s_block_end("content")
    s_word(6, name="type", endian='>')
    s_word(1, name="class", endian='>')

    #ANY
    s_initialize("ANY")
    s_word(65535, name="TransactionID", fuzzable=True)
    s_word(256, name="Flags", endian='>')
    s_word(1, name="Questions", endian='>')
    s_word(0, name="Answer", endian='>')
    s_word(0, name="Authority", endian='>')
    s_word(0, name="Additional", endian='>')
    s_block_start("content", None, genContent)
    s_string("www.baidu.com")
    s_block_end("content")
    s_word(255, name="type", endian='>')
    s_word(1, name="class", endian='>')

    sess.connect(s_get("A"))

    sess.fuzz(path, target, params)


if __name__ == "__main__":
    target_ip = "127.0.0.1"
    pport = 53
    path = "/home/dongjian/dns/dnspod-afl-test/src/"
    target = "dnspod-sr"
    params = []
    fuzz(target_ip, pport, path, target, params, script_start=True)