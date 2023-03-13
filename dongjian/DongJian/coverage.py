'''

Author: Josh Woo(Wuchunming)
Corp: CETCSC

this file is a library used to setup, read, set and get shared memory shared by the target program.
the target program may to be a net protocol service program.
we modified AFL's instrumental ways to instrument the target program, but we remove the fork_server from it, because
almost all the net protocol service program is providing service not like the file handling program.

if there are any questions, plz contact 970642163@qq.com

'''
import time
from urllib.parse import urlencode
import httplib2
import json

req = httplib2.Http()
resp = None
content = None
ip = "http://"
port = None


def set_ip(_ip):
    global ip
    ip = ip + _ip + ":"


def set_port(_port):
    global port
    port = str(_port)


def init(txt_filename):
    global req, resp, content, ip, port
    data = {
        "txt_filename": txt_filename,
    }
    resp, content = req.request(uri=ip + port + "/api/coverage/init", method='POST', body=json.dumps(data),
                                headers={"Content-Type": 'application/json'})

def stop_target():
    global req, resp, content, ip, port
    resp, content = req.request(ip + port + "/api/coverage/stop_target", 'GET')

# set the shared memory to 0
def set_shm():
    global req, resp, content, ip, port
    resp, content = req.request(ip + port + "/api/coverage/set_shm", 'GET')


# init the shared memory dictionary, useless now(invalid now)!
def init_cov():
    global req, resp, content, ip, port
    resp, content = req.request(ip + port + "/api/coverage/init_cov", 'GET')

# setup the shared memory
def setup_shm():
    global req, resp, content, ip, port
    resp, content = req.request(ip + port + "/api/coverage/setup_shm", 'GET')


# setup the environment variables
def setup_env():
    global req, resp, content, ip, port
    resp, content = req.request(ip + port + "/api/coverage/setup_env", 'GET')


# start the target program
def spwan_target(path, target, param=[]):
    global req, resp, content, ip, port
    data = {
        "path":path,
        "target_name": target,
        "param": param
    }
    resp, content = req.request(uri=ip + port + "/api/coverage/spwan_target", method='POST', body=json.dumps(data), headers={"Content-Type": 'application/json'})

def has_new_bit():
    global req, resp, content, ip, port
    resp, content = req.request(ip + port + "/api/coverage/has_new_bit", 'GET')
    hsnbit = json.loads(content)
    return hsnbit['hasnb']

def get_cov():
    global req, resp, content, ip, port
    resp, content = req.request(ip + port + "/api/coverage/get_cov", 'GET')
    cov = json.loads(content)
    return cov['cv_old'], cov['cv']

def check():
    global req, resp, content, ip, port
    resp, content = req.request(ip + port + "/api/coverage/check", 'GET')
    res = json.loads(content)
    return res['status'] == 0


# just for test, it is useless in fact
if __name__=="__main__":
    setup_shm()
    setup_env()
    spwan_target("/home/dongjian/dnspodsr/src/", "dnspod-sr", [])
    has_new_bit()
    # set_shm()
    time.sleep(1)
    has_new_bit()
    while True:
        time.sleep(1)
        get_cov()



