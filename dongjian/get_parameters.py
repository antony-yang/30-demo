# from DongJian.utils import CommonDBhandler
# import json
# connetion = CommonDBhandler.handler.getCon2()
# sql = "select * from proto_param_info"
# cur = connetion.cursor()
# cur.execute(sql)
# params = iter(cur._rows)
#
# for param in params:
#     proto_name = param[1]
#     proto_param = param[2]
#     file = open("./parameters/" + proto_name + ".txt", "w")
#     file.writelines(proto_param + "\r\n")
#     file.close()
# connetion.close()

import os

protos = {}
protos2 = []
for parent, _, filenames in os.walk("script"):
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

print(protos)
print(protos2)
