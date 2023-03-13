import os
import shutil
# from netzob.all import *
import time

from DongJian.utils import DBhandler
import flask
from flask import Flask, redirect, render_template, send_from_directory, request, make_response, Response,send_file
from concurrent.futures import ThreadPoolExecutor

from web_ui import web_config

MAX_LOG_LINE_LEN = 1500
app = Flask(__name__)
app.session = None
dbhander = DBhandler.dbhandler()
# my_netzob_db =dbhander.getMC()['netzob']
# mycol = my_netzob_db['result']
executor = ThreadPoolExecutor()

@app.after_request
def after_request(resp):
    resp.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization.session_id')
    resp.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS,HEAD')
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

@app.route("/api/get_all_protocol")
def get_all_protocol():
    return flask.jsonify(app.session.get_all_protocol())


@app.route("/api/get_task_list")
def get_task_list():
    return flask.jsonify(app.session.get_task_list())


@app.route("/api/get_task_list_by_page/<int:page_id>")
def get_task_list_by_page(page_id):
    return flask.jsonify(app.session.get_task_list_by_page(page_id))


@app.route("/api/get_task_list_total_page")
def get_task_list_total_page():
    return flask.jsonify(app.session.get_task_list_total_page())


@app.route("/api/get_task_result", methods=['POST'])
def get_task_result():
    if request.method == 'POST':
        param = request.json
        return flask.jsonify(app.session.get_task_result(param))
    return []


@app.route("/api/log", methods=['POST'])
def log():
    if request.method == 'POST':
        param = request.json
        return flask.jsonify(app.session.log(param))
    return {"code": 400, "msg": "Request type is not post!", "token": web_config.token}

@app.route("/api/progress", methods=['POST'])
def progress():
    if request.method == 'POST':
        param = request.json
        return flask.jsonify(app.session.progress(param))
    return {"code": 400, "msg": " Request type is not post!!", "token": web_config.token}


@app.route("/api/result", methods=['POST'])
def result():
    if request.method == 'POST':
        param = request.json
        if param["type"] == 1:
            return flask.jsonify(app.session.get_task_result1(param))
        if param["type"] == 2:
            document = app.session.get_task_result2(param)
            if "code" in document:
                return flask.jsonify(document)
            else:
                return send_from_directory("../zip/", document)
        if param["type"] == 3:
            return flask.jsonify(app.session.get_task_result3(param))
        return {"code": 400, "msg": "Wrong type!", "token": web_config.token}
    return {"code": 400, "msg": " Request type is not post!!", "token": web_config.token}


@app.route("/api/get_task_result_by_page/<int:page_id>", methods=['POST'])
def get_task_result_by_page(page_id):
    if request.method == 'POST':
        param = request.json
        return flask.jsonify(app.session.get_task_result_by_page(param, page_id))
    return []


@app.route("/api/get_task_result_total_page", methods=['POST'])
def get_task_result_total_page():
    if request.method == 'POST':
        param = request.json
        return flask.jsonify(app.session.get_task_result_total_page(param))
    return []


@app.route("/api/get_task_crash_by_page/<int:page_id>", methods=['POST'])
def get_task_crash_by_page(page_id):
    if request.method == 'POST':
        param = request.json
        return flask.jsonify(app.session.get_task_crash_by_page(param, page_id))
    return []


@app.route("/api/get_task_crash_total_page", methods=['POST'])
def get_task_crash_total_page():
    if request.method == 'POST':
        param = request.json
        return flask.jsonify(app.session.get_task_crash_total_page(param))
    return []


@app.route("/api/get_task_parameter", methods=['POST'])
def get_task_parameter():
    if request.method == 'POST':
        param = request.json
        return flask.jsonify(app.session.get_task_parameter(param))
    return []


@app.route("/api/start_task", methods=['POST'])
def start_task():
    if request.method == "POST":
        param = request.json
        try:
            res = app.session.start_task(param)
            return flask.jsonify(res)
        except Exception as e:
            print(e)
            return flask.jsonify({"res": 0, "value": str(e)})
    return flask.jsonify({"res": 0, "value": "request type is not post"})


@app.route("/api/create_and_start_task", methods=['POST'])
def create_and_start_task():
    if request.method == "POST":
        param = request.json
        try:
            res = app.session.create_and_start_task(param)
            return flask.jsonify(res)
        except Exception as e:
            print(e)
            return flask.jsonify({"res": 0, "value": str(e)})
    return flask.jsonify({"res": 0, "value": "request type is not post"})


@app.route("/api/create_task", methods=['POST'])
def create_task():
    if request.method == "POST":
        param = request.json
        try:
            res = app.session.create_task(param)
            return flask.jsonify(res)
        except Exception as e:
            print(e)
            return flask.jsonify({"res": 0, "value": str(e)})
    return flask.jsonify({"res": 0, "value": "request type is not post"})


@app.route("/api/delete_task", methods=['POST'])
def delete_task():
    if request.method == 'POST':
        param = request.json
        if "run_id" in param:
            return flask.jsonify(app.session.delete_task(param))
        if "taskIds" in param:
            return flask.jsonify(app.session.delete_tasks(param))
        else:
            return {"code": 400, "msg": " Lacking paramter!", "token": web_config.token}
    return {"code": 400, "msg": " Request type is not post!", "token": web_config.token}


@app.route("/api/delete_tasks", methods=['POST'])
def delete_tasks():
    if request.method == 'POST':
        param = request.json
        return flask.jsonify(app.session.delete_tasks(param))
    return []


@app.route("/api/get_running_task")
def get_running_task():
    return flask.jsonify(app.session.get_running_task())


@app.route("/api/kill_all_running_task")
def kill_all_task():
    try:
        return app.session.kill_all_running_task()
    except Exception as e:
        print(e)
        return {"res": 0, "value": str(e)}


@app.route("/api/kill_task_by_name", methods=["POST"])
def kill_task_by_name():
    if request.method == "POST":
        param = request.json
        try:
            res = app.session.kill_task_by_name(param)
            return flask.jsonify(res)
        except Exception as e:
            print(e)
            return flask.jsonify({"res": 0, "value": str(e)})
    return flask.jsonify({"res": 0, "value": "request type is not post"})


@app.route("/api/get_deault_task_params", methods = ["POST"])
def get_task_params():
    if request.method == "POST":
        param = request.json
        res = app.session.get_deault_task_params(param)
        return flask.jsonify(res)
    return flask.jsonify({"res": 0, "value": "request type is not post"})


@app.route("/api/suspend")
def suspend_all_task():
    try:
        return app.session.suspend_all_task()
    except Exception as e:
        print(e)
        return {"res": 0}


@app.route("/api/resume")
def resume_all_task():
    try:
        return app.session.resume_all_task()
    except Exception as e:
        print(e)
        return {"res": 0}


@app.route("/api/suspend_task_by_name", methods=['POST'])
def suspend_task_by_name():
    if request.method == "POST":
        param = request.json
        try:
            res = app.session.suspend_task_by_name(param)
            return flask.jsonify(res)
        except Exception as e:
            print(e)
            return flask.jsonify({"res": 0, "value": str(e)})
    return flask.jsonify({"res": 0, "value": "request type is not post"})


@app.route("/api/resume_task_by_name", methods=['POST'])
def resume_task_by_name():
    if request.method == "POST":
        param = request.json
        try:
            res = app.session.resume_task_by_name(param)
            return flask.jsonify(res)
        except Exception as e:
            print(e)
            return flask.jsonify({"res": 0, "value": str(e)})
    return flask.jsonify({"res": 0, "value": "request type is not post"})


@app.route("/api/control", methods=['POST'])
def control():
    if request.method == "POST":
        param = request.json
        try:
            res = app.session.control(param)
            return flask.jsonify(res)
        except Exception as e:
            print(e)
            return flask.jsonify({"code": 400, "msg": str(e), "token": web_config.token})
    return flask.jsonify({"code": 400, "msg": "request type is not post", "token": web_config.token})


@app.route("/api/status", methods=['POST'])
def status():
    if request.method == "POST":
        param = request.json
        try:
            res = app.session.status(param)
            return flask.jsonify(res)
        except Exception as e:
            print(e)
            return flask.jsonify({"code": 400, "msg": str(e), "token": web_config.token})
    return flask.jsonify({"code": 400, "msg": "request type is not post", "token": web_config.token})


@app.route("/api/download", methods=['POST'])
def download():
    if request.method == "POST":
        param = request.json
        filename = app.session.get_file_name(param)
        if filename is not None:
            filename = filename + ".zip"
        else:
            return flask.jsonify({"res": 0, "value": "task not exists"})
        path = os.path.join(os.path.expanduser('~'), "result")
        if os.path.exists(path):
            pass
        else:
            return flask.jsonify({"res": 0, "value": "result not exists"})
        for root, dirs, files in os.walk(os.path.join(os.path.expanduser('~'), "result")):
            for file in files:
                rf = os.path.splitext(file)[0] + os.path.splitext(file)[1]
                if rf == filename:
                    # return send_from_directory(os.path.join(os.path.expanduser('~'), "result"), filename=filename,
                    #                            as_attachment=True)
                    store_path = os.path.join(os.path.expanduser('~'), "result") + "/" + rf

                    def send_file():
                        with open(store_path, 'rb') as target_file:
                            while 1:
                                data = target_file.read(2 * 1024 * 1024)  # 每次读取20M
                                if not data:
                                    break
                                yield data

                    response = Response(send_file(), content_type='application/octet-stream')
                    response.headers[
                        "Content-disposition"] = 'attachment; filename=%s' % filename
                    return response
            break
        return flask.jsonify({"res": 0, "value": "file not exists"})
    return flask.jsonify({"res": 0, "value": "request type is not post"})


@app.route("/api/download2")
def download2():
    run_id = request.args.get("run_id")
    filename = app.session.get_file_name({"run_id": run_id})
    filename = filename + ".zip"
    if filename is not None:
        path = os.path.join(os.path.expanduser('~'), "result")
        if os.path.exists(path):
            pass
        else:
            return flask.jsonify({"res": 0, "value": "result not exists"})
        for root, dirs, files in os.walk(os.path.join(os.path.expanduser('~'), "result")):
            for file in files:
                rf = os.path.splitext(file)[0] + os.path.splitext(file)[1]
                if rf == filename:
                    # return send_from_directory(os.path.join(os.path.expanduser('~'), "result"), filename=filename,
                    #                            as_attachment=True)
                    store_path = os.path.join(os.path.expanduser('~'), "result") + "/" + rf

                    def send_file():
                        with open(store_path, 'rb') as target_file:
                            while 1:
                                data = target_file.read(2 * 1024 * 1024)  # 每次读取20M
                                if not data:
                                    break
                                yield data

                    response = Response(send_file(), content_type='application/octet-stream')
                    response.headers[
                        "Content-disposition"] = 'attachment; filename=%s' % filename
                    return response
            break
        return flask.jsonify({"res": 0, "value": "file not exists"})
    else:
        return flask.jsonify({"res": 0, "value": "no such file"})
    # store_path = os.path.join(os.path.expanduser('~'), "result") + "/" + filename
    # def send_file():
    #     with open(store_path, 'rb') as target_file:
    #         while 1:
    #             data = target_file.read(20 * 1024 * 1024)  # 每次读取20M
    #             if not data:
    #                 break
    #             yield data
    # response = Response(send_file(), content_type='application/octet-stream')
    # response.headers[
    #     "Content-disposition"] = 'attachment; filename=%s.txt' % filename
    # return response


#netzob
'''
@app.route("/api/netzob", methods = ['get', 'POST'])
def netzob():
   bpfFilter = request.form['bpfFilter']
   importLayer = request.form['importLayer']
   if request.method == 'POST':
    try:
        file_path_list = []
        file_info_list = []
        file_name_list = []
        for f in request.files.getlist('file'):
            if f.filename != "":
                save_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                file_name = f.filename
                md5_file_name = hashlib.md5((str(time.time()) + f.filename[:-5]).encode('utf8')).hexdigest() + '.pcap'
                file_path = os.path.join('/data/upload', md5_file_name)
                file_name_list.append(file_name)
                file_path_list.append(file_path)
                file_info_list.append({'file_name': file_name, 'md5_file_name': md5_file_name, 'save_time': save_time,
                                       'file_path': file_path})
                f.save(file_path)
        t = threading.Thread(target=get_symbols, args=(file_path_list, file_info_list, file_name_list, bpfFilter, importLayer))
        t.start()

        return flask.jsonify({"res": 1, "desc": "pcap file uploaded successfully!", "symbol_list": "symbols_value_list"})

    except Exception as e:
        print(e)
        return flask.jsonify({"res": 0, "value": str(e)})


def get_symbols(file_path_list , file_info_list, file_name_list , bpfFilter , importLayer):
    try:
        mess = PCAPImporter.readFiles(filePathList=file_path_list,
                                    bpfFilter=str(bpfFilter), importLayer=int(importLayer)).values()
        symbolAlign = Symbol(messages=mess)
        Format.splitAligned(symbolAlign)
        symbols = Format.clusterByKeyField(symbolAlign, symbolAlign.fields[0])
        format_len = format(len(symbols))
        symbols_value_list = []
        for sym in symbols.values():
                Format.splitAligned(sym.fields[0], doInternalSlick=True)
                symbols_value_list.append(str(sym))
        task_name = reduce(lambda x, y: x + "_" + y, file_name_list) + "_" + str(
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))

        result = {'task_name': task_name, 'file_info_list': file_info_list, 'symbol': symbols_value_list}
        x = mycol.insert_one(result)
    except Exception as e:
        print(e)

# @app.route("/api/netzob", methods = ['get', 'POST'])
# def netzob():
#    bpfFilter = request.form['bpfFilter']
#    importLayer = request.form['importLayer']
#    if request.method == 'POST':
#     try:
#         file_path_list = []
#         file_info_list = []
#         file_name_list = []
#         for f in request.files.getlist('file'):
#             if f.filename != "":
#                 save_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
#                 file_name = f.filename
#                 md5_file_name = hashlib.md5((str(time.time()) + f.filename[:-5]).encode('utf8')).hexdigest() + '.pcap'
#                 file_path = os.path.join('/data/upload', md5_file_name)
#                 file_name_list.append(file_name)
#                 file_path_list.append(file_path)
#                 file_info_list.append({'file_name': file_name, 'md5_file_name': md5_file_name, 'save_time': save_time,
#                                        'file_path': file_path})
#                 f.save(file_path)
#         mess = None
#         for file_path in file_path_list:
#             if mess:
#                 message_session = PCAPImporter.readFile(filePath=file_path, bpfFilter=str(bpfFilter), importLayer=int(importLayer)).values()
#                 mess = mess + message_session
#                 pass
#             else:
#                 mess = PCAPImporter.readFile(filePath=file_path, bpfFilter=str(bpfFilter), importLayer=int(importLayer)).values()
#
#         symbolAlign = Symbol(messages=mess)
#         Format.splitAligned(symbolAlign)
#         symbols = Format.clusterByKeyField(symbolAlign,symbolAlign.fields[0])
#         format_len = format(len(symbols))
#         symbols_value_list = []
#         for sym in symbols.values():
#                 Format.splitAligned(sym.fields[0], doInternalSlick=True)
#                 symbols_value_list.append(str(sym))
#         # mydict = {}
#         # i = 0
#         # for field in res.fields:
#         #     all_mess = []
#         #     for message in field.messages:
#         #         all_mess.append(str(message))
#         #         print(str(message))
#         #     mydict["field" + str(i)] = all_mess
#         #     i+= 1
#         task_name = reduce(lambda x, y: x + "_" + y, file_name_list) + "_" + str(
#             time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
#
#         result = {'task_name': task_name, 'file_info_list': file_info_list, 'symbol': symbols_value_list}
#         x = mycol.insert_one(result)
#         return flask.jsonify({"res": 1, "desc": "pcap file uploaded successfully!", "symbol_list": symbols_value_list})
#
#     except Exception as e:
#         print(e)
#         return flask.jsonify({"res": 0, "value": str(e)})


@app.route("/api/get_netzob_list_by_page/<int:page_id>")
def get_netzob_list_by_page(page_id):
    return flask.jsonify(app.session.get_netzob_list_by_page(page_id))


@app.route("/api/get_netzob_list_total_page")
def get_netzob_list_total_page():
    return flask.jsonify(app.session.get_netzob_list_total_page())


@app.route("/api/get_netzob_info", methods=['POST'])
def get_netzob_info():
    if request.method == 'POST':
        param = request.form
        return flask.jsonify(app.session.get_netzob_info(param))
    return []
'''
# backup dbs

@app.route("/api/backup", methods=['POST'])
def backup():
    if request.method == "POST":
        param = request.json
        return flask.jsonify(app.session.backup_data(param))
        # executor.submit(app.session.backup_data, param)
        # return flask.jsonify({"code": 200, "msg": "start backup and wait for push", "token": web_config.token})
    return flask.jsonify({"code": 400, "msg": "It's not a post method.", "token": web_config.token})

# restore dbs
@app.route("/api/restore", methods=['POST'])
def restore():
    # data_data = request.files['file']
    # executor.submit(app.session.restore_data, data_data)
    if request.method == "POST":
        param = request.json
        return flask.jsonify(app.session.restore_data(param))
        # executor.submit(app.session.restore_data, param)
        # return flask.jsonify({"code": 200, "msg": "waiting for restore", "token": web_config.token})
    return flask.jsonify({"code": 400, "msg": "It's not a post method.", "token": web_config.token})

# pacap gen
@app.route("/api/gen_pcap/")
def gen_pcap():
    TMP_PATH = "../tmp"
    run_id = request.args.get("run_id")
    if os.path.exists("{}/{}.tar.gz".format(TMP_PATH, run_id)):
        return flask.jsonify({"res":1, "value": "this run_id pcap is already generated."})
    # if os.path.exists(TMP_PATH):
    #     shutil.rmtree(TMP_PATH)
    # executor.submit(app.session.gen_pcap, run_id)
    try:
        res = app.session.gen_pcap(run_id)
        return flask.jsonify(res)
    except Exception as e:
        return flask.jsonify({"res": 0, "value": "please wait for a few seconds."})

# pacap get
@app.route("/api/get_pcap/")
def get_pacp():
    TMP_PATH = "../tmp"
    run_id = request.args.get("run_id")
    pcapzip = "{}/{}.tar.gz".format(TMP_PATH, run_id)
    def send_file():
        with open(pcapzip, 'rb') as target_file:
            while 1:
                data = target_file.read(2 * 1024 * 1024)
                if not data:
                    break
                yield data
    response = Response(send_file(), content_type='application/octet-stream')
    response.headers[
        "Content-disposition"] = 'attachment; filename=%s.tar.gz' % run_id
    return response

# test case pcap replay
@app.route("/api/replay_pcap/<run_id>/<case_id>")
def replay_pcap(run_id, case_id):
    return flask.jsonify(app.session.replay_pcap(run_id, case_id))


@app.route("/api/export_document/<document>")
def export_document(document):
    if document.split('.')[-1] not in ["doc", "pdf", "xls", "xml"]:
        return flask.jsonify({"res": 0, "value": "format error!"})
    report = app.session.export_document(document)
    if report is None:
        return flask.jsonify({"res": 0, "value": "has no report!"})
    return send_from_directory(report, document)



@app.route("/")
def index():
    return render_template("tableWeb.html")


@app.route("/upload")
def upload():
    return render_template("upload.html")


@app.route("/tableWeb")
def tableWeb():
    return render_template("tableWeb.html")


@app.route("/index")
def index2():
    return render_template("index.html")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(os.path.join(app.root_path, "static"), "favicon.ico", mimetype="image/vnd.microsoft.icon")


@app.route("/index2")
def index3():
    return render_template("index2.html")


@app.route("/showResult.html")
def showResult():
    return render_template("showResult.html")


@app.route("/addTaskModel.html")
def addTaskModel():
    return render_template("addTaskModel.html")