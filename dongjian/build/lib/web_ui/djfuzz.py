import datetime
import multiprocessing
import os
import sys
import getopt

protos = {}
protos2 = []
for parent, _, filenames in os.walk("../script"):
    for name in filenames:
        if name.startswith("."):
            continue
        if name.endswith("py"):
            script_obj = None
            script_name = name.split('.')[0]
            code = "from script import " + script_name + " as script_obj"
            exec(code)
            protos[script_name] = script_obj
            protos2.append(script_name)
        else:
            continue


def help():
    print("-----------------------------------------------------------------------\r\n"
          "              Dongjian Protocol Fuzzing System  V0.0.1.0\r\n"
          "\r\n"
          "                                       --by CETCSC Corporation limited.\r\n"
          " if there are any problems, plz contact 970642163@qq.com(josh woo)     \r\n"
          "-----------------------------------------------------------------------\r\n"
          "\r\n" 
          "djfuzz -h|--help for help\r\n"
          "\r\n"
          "-----------------------------------------------------------------------\r\n"
          "usage:\r\n"
          "\r\n" 
          "      djfuzz -p protocol [options]\r\n"
          "\r\n"
          "-----------------------------------------------------------------------\r\n"
          "options:\r\n"
          "\r\n"
          "        --target_ip, the ip address of the target, necessary\r\n"
          "        --dport, the debug port, necessary\r\n"
          "        --pport, the protocol port, necessary\r\n"
          "        --start_cmds, the start commands, necessary\r\n"
          "        --proc_name, the process's name, necessary\r\n"
          "        --dst_ip, the ip address of the destination, optional\r\n"
          "        --net_interface, the net interface's name, optional\r\n"
          "        --dst_mac, the mac address of the destination, optional\r\n"
          "        --serial_port, the serial port, optional\r\n"
          "        --Baudrate, the Baudrate only for serial port fuzzing, optional\r\n"
          "\r\n" 
          "-----------------------------------------------------------------------\r\n"
          )


def parse(options, list):
    for opt, val in options:
        if opt in list:
            return val
    return None

def main():
    taskname="Console_Fuzzing" + datetime.datetime.utcnow().isoformat().replace(":", "-").replace(".", "-")
    tasktype="Fuzzing"
    taskcreator="Console"
    protocol = None
    target_ip = None
    dport = None
    pport = None
    start_cmds = None
    proc_name=None
    if len(sys.argv) < 2:
        help()
    else:
        try:
            options, args = getopt.getopt(sys.argv[1:], shortopts="p:h", longopts=["help", "target_ip=", "dport=", "pport=", "start_cmds=", "proc_name=", "dst_ip=", "net_interface=", "dst_mac=", "l2_dst=", "serial_port=", "Baudrate="])
            print(options)
            print(args)
            h = parse(options, ["-h", "--help"])
            if h is not None:
                help()
            else:
                protocol = parse(options, ["-p"])
                target_ip = parse(options, ["--target_ip"])
                start_cmds = parse(options, ["--start_cmds"])
                proc_name = parse(options, ["--proc_name"])
                pport = int(parse(options, ["--pport"]))
                dport = int(parse(options, ["--dport"]))
                dst_ip = parse(options, ["--dst_ip"])
                dst_mac = parse(options, ["--dst_mac"])
                l2_dst = parse(options, ["--l2_dst"])
                net_interface = parse(options, ["--net_interface"])
                serial_port = parse(options, ["--serial_port"])
                Baudrate = parse(options, ["--Baudrate"])
                kwargs = {}
                kwargs["dst_ip"] = dst_ip
                kwargs["dst_mac"] = dst_mac
                kwargs["l2_dst"] = l2_dst
                kwargs["net_interface"] = net_interface
                kwargs["serial_port"] = serial_port
                kwargs["Baudrate"] = Baudrate
                kwargs['target_ip'] = target_ip
                kwargs['start_cmds'] = start_cmds
                kwargs['proc_name'] = proc_name
                kwargs['pport'] = pport
                kwargs['dport'] = dport
                kwargs['protocol'] = protocol
                kwargs['taskname'] = taskname
                kwargs['tasktype'] = tasktype
                kwargs['taskcreator'] = taskcreator

                kwargs['script_start'] = True

                print(kwargs)

                if protocol is None or target_ip is None or start_cmds is None or proc_name is None or pport is None or dport is None:
                    print("lack parameter")
                else:
                    if protocol in protos.keys():
                        process = multiprocessing.Process(target=protos[protocol].fuzz, kwargs=kwargs)
                        process.start()

        except getopt.error as e:
            print(str(e))


if __name__=="__main__":
    main()
