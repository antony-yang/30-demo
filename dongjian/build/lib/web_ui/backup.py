import datetime
import os
import shutil

from DongJian.utils import db_config
from DongJian.utils.guan_http import GuanHTTP

def backup():
    currenttime = datetime.datetime.now().isoformat().replace(":", "-").replace(".", "-")
    BACKUP_PATH = "./backup"
    if not os.path.exists(BACKUP_PATH):
        os.makedirs(BACKUP_PATH + "/" + currenttime)

    # backup mysql
    dump_mysql_cmd = "/usr/bin/mysqldump -h {} -u {} -p'{}' {} --single-transaction > {}/{}/mysql 2>/dev/null".format(
        db_config.db_host,
        db_config.db_user,
        db_config.db_passwd,
        db_config.db_name,
        BACKUP_PATH,
        currenttime)
    os.system(dump_mysql_cmd)

    # backup mongo
    dump_mongo_cmd = "/usr/bin/mongodump -h {} -u {} -p {} -d {} --authenticationDatabase admin -o {}/{}/mongo".format(
        db_config.db_host,
        db_config.db_user,
        db_config.db_passwd,
        db_config.db_name,
        BACKUP_PATH,
        currenttime)
    os.system(dump_mongo_cmd)
    # compress
    comresscmd = "/bin/tar czf {0}.tar.gz {0}".format(BACKUP_PATH + "/" + currenttime)
    os.system(comresscmd)

    # guan kong platform backup url
    url = "http://192.168.182.230/test.php"
    uploadhttp = GuanHTTP()
    files = {
        "file": (currenttime + ".tar.gz", open(BACKUP_PATH + "/" + currenttime + ".tar.gz", "rb"))
    }
    response = uploadhttp.post(url=url, files=files)
    if response["res"] == 0:
        print("upload failture: %s" % str(response["value"]))
    else:
        print("upload file %s success" % response["value"].text)
    shutil.rmtree(BACKUP_PATH)

def restore(data_date):
    RESTORE_PATH = "./backup"
    if not os.path.exists(RESTORE_PATH):
        os.mkdir(RESTORE_PATH)

    url = "http://192.168.182.230/dongjian/backup/%s.tar.gz" % data_date
    downloadhttp = GuanHTTP()
    response = downloadhttp.getFile(url, "{}/{}.tar.gz".format(RESTORE_PATH, data_date))
    if response["res"] == 0:
        return {"res": 0, "value": response["value"]}
    # decompress
    decompresscmd = "/bin/tar xzf {}.tar.gz".format(RESTORE_PATH + "/" + data_date)
    os.system(decompresscmd)

    load_mysql_cmd = "/usr/bin/mysql -h {} -u {} -p'{}' {} < {}/{}/mysql 2>/dev/null".format(
        db_config.db_host,
        db_config.db_user,
        db_config.db_passwd,
        db_config.db_name,
        RESTORE_PATH,
        data_date)
    os.system(load_mysql_cmd)

    load_mongo_cmd = "/usr/bin/mongorestore -h {} -u {} -p {} -d {} --drop --authenticationDatabase admin {}/{}/mongo/{}".format(
        db_config.db_host,
        db_config.db_user,
        db_config.db_passwd,
        db_config.db_name,
        RESTORE_PATH,
        data_date,
        db_config.db_name
    )
    os.system(load_mongo_cmd)
    shutil.rmtree(RESTORE_PATH)

