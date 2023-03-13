#!/usr/bin/python

import datetime as dt

from DongJian import *
param = {
    "param":
        {
        "dport": {"ness": 0, "default": 26002},
        "pport": {"ness": 1, "default": 53},
        "proc_name": {"ness": 0, "default": ""},
        "target_ip": {"ness": 1, "default": "127.0.0.1"},
        "start_cmds": {"ness": 0, "default": []}
        },
        "proto": "dns"
    }

def update_time(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    node.names['time']._value = dt.datetime.strftime(dt.datetime.now(), '%Y-%m-%d  %H:%M:%S')
    node.names['message_sequence']._value = node._mutant_index


def fuzz(start_cmds, proc_name, target_ip, pport, dport,  *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(target_ip, pport, proto="udp"),
            # procmon=pedrpc.Client(target_ip, dport),
            # procmon_options={"start_commands": [start_cmd]},
        ),
        **kwargs
    )

    s_initialize('demo')
    with s_block('HDR'):
        s_byte(value=1, full_range=True, name='version')
        s_byte(value=1, full_range=True, name='protocol_type')
        s_byte(value=0x21, full_range=True, name='message_type')
        s_byte(value=0, full_range=True, name='reserved')
        s_dword(value=0x09, endian='>', name='IDa')
        s_dword(value=0x0414, endian='>', name='IDb')
        s_dword(value=0x0, endian='>', name='sessionID')
        s_dword(value=0x0, endian='>', name='message_sequence')
        s_size(block_name='Message', endian='>', name='message_length')
        s_dword(value=0, endian='>', name='partition_length')
        s_dword(value=0, endian='>', name='partition_offset')

    with s_block('Message'):
        s_byte(value=0, full_range=True, name='flag')
        s_byte(value=0, full_range=True, name='device_ID')
        s_word(value=0x0502, endian='>', name='command')
        s_dword(value=0, endian='>', name='IDa_in_message')
        s_dword(value=0, endian='>', name='send_flag')
        s_dword(value=0, endian='>', name='receive_flag')
        s_string(value=dt.datetime.strftime(dt.datetime.now(), '%Y-%m-%d  %H:%M:%S'), size=20, fuzzable=False, name='time')

    sess.connect(s_get("demo"), callback=update_time)
    sess.fuzz()


if __name__ == "__main__":
    target_ip = "10.38.4.15"
    start_cmds = []
    proc_name = ""
    pport = 53
    dport=26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
