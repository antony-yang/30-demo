import datetime
import os
import signal
import threading

import psutil
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.wsgi import WSGIContainer

from DongJian.utils import CommonDBhandler
from web_ui import wsession, web_config
from web_ui.app import app
from DongJian.utils.guan_http import GuanHTTP
from time import sleep


def exit2(signum, frame):
    exit()


def reset_all_database():
    _m_db = CommonDBhandler.handler.getMC()["dongjian"]
    task_list_db = _m_db["task_list"]
    task_list_db.update_many ({}, {'$set': {"status": "finished"}})


def send_heart():
    url = web_config.heart_monitor_url
    request = GuanHTTP()
    args = {"token": web_config.token, "bianm": web_config.bianma}
    while True:
        try:
            response = request.post(url=url, json=args)
            sleep(30)
        except Exception as e:
            print("can't reach heart_monitor_url")


def send_machine_status():
    url = web_config.machine_monitor_url
    request = GuanHTTP()
    status = {}
    status["hostname"] = os.uname()[1]
    status["version"] = os.uname()[3]
    status["versionDetail"] = os.uname()[2]
    status["menPer"] = str(psutil.virtual_memory().percent)
    status["menSize"] = str(round(psutil.virtual_memory().total/1024/1024/1024,2)) + " GB"
    status["cpuCoreNum"] = str(psutil.cpu_count())
    status["cpuPer"] = str(psutil.cpu_percent())
    f = open("/proc/cpuinfo")
    while True:
        line = f.readline()
        if "model name" in line:
            status["cpuXh"] = line.split(": ")[1]
            break
    args = {"token": web_config.token, "bianm": web_config.bianma, "msg": "send machine status", "data": status}
    print(args)
    while True:
        try:
            # print()
            response = request.post(url=url, json=args)
            sleep(3600)     # wait 1h
        except Exception as e:
            print("can't reach machine_monitor_url")

def main():
    reset_all_database()
    address = "0.0.0.0"
    port = 666
    signal.signal(signal.SIGINT, exit2)
    signal.signal(signal.SIGTERM, exit2)
    w = wsession.Wsession()
    app.session = w
    # app.run(address, port)

    http_server = HTTPServer(WSGIContainer(app), ssl_options={
           "certfile": os.path.join(os.path.abspath("."), "server.crt"),
           "keyfile": os.path.join(os.path.abspath("."), "server.key"),
    }, max_buffer_size=504857600)

    # http_server = HTTPServer(WSGIContainer(app), max_buffer_size=504857600)
    http_server.listen(port, address=address)
    flask_thread = threading.Thread(target=IOLoop.instance().start)
    flask_thread.daemon = True
    if not flask_thread.isAlive():
        flask_thread.start()
    heart = threading.Thread(target=send_heart)
    heart.start()
    machine_status = threading.Thread(target=send_machine_status)
    machine_status.start()
    while True:
        pass


if __name__ == "__main__":
    main()