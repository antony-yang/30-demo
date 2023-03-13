import pymysql

from DBUtils.PooledDB import PooledDB
from DongJian.utils import db_config
import pymongo

class dbhandler(object):

    def __init__(self):
        self.pool = None
        self.pool2 = None

    def getCon(self):   # read
        if self.pool is None:
            self.pool = PooledDB(pymysql, db_config.max_connections, host=db_config.db_host, user=db_config.db_user, passwd=db_config.db_passwd, db=db_config.db_name, port=db_config.db_port, charset=db_config.db_charset)
        con = self.pool.connection()
        return con

    def getCon2(self):  # write
        if self.pool2 is None:
            self.pool2 = PooledDB(pymysql, db_config.max_connections, host=db_config.db_host, user=db_config.db_user, passwd=db_config.db_passwd, db=db_config.db_name, port=db_config.db_port, charset=db_config.db_charset)
        con = self.pool2.connection()
        return con

    def getMC(self):
        return pymongo.MongoClient(host=db_config.db_host, port=db_config.mdb_port, username=db_config.db_user, password=db_config.db_passwd)
