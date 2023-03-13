from __future__ import print_function

import collections
import datetime
import sqlite3
import sys
import base64
import six
import pymysql
from DongJian.utils import db_config
from . import data_test_case, data_test_step, exception, helpers, ifuzz_logger_backend
from DongJian.utils import DBhandler
from .utils import CommonDBhandler

# fixup for buffer in python 3
if sys.version_info.major > 2:
    buffer = memoryview


def hex_to_hexstr(input_bytes):
    """
    Render input_bytes as ASCII-encoded hex bytes, followed by a best effort
    utf-8 rendering.

    :param input_bytes: Arbitrary bytes.
    :return: Printable string.
    """
    return helpers.hex_str(input_bytes)


DEFAULT_HEX_TO_STR = hex_to_hexstr


def get_time_stamp():
    s = datetime.datetime.utcnow().isoformat()
    return s


class FuzzLoggerDbM(ifuzz_logger_backend.IFuzzLoggerBackend):
    """Log fuzz data in a sqlite database file."""

    def __init__(self, db_filename, num_log_cases=0):

        self.collection_name = db_filename
        self._db_handler = CommonDBhandler.handler
        self._m_db = self._db_handler.getMC()['dongjian']
        self._m_db_collection_cases = self._m_db[self.collection_name+"-cases"]
        self._m_db_collection_steps = self._m_db[self.collection_name+"-steps"]

        self._current_test_case_index = 0

        self._queue = collections.deque([])  # Queue that holds last n test cases before commiting
        self._queue_max_len = num_log_cases
        self._fail_detected = False
        self._log_first_case = True
        self._data_truncate_length = 512

    def get_test_case_data(self, index):
        try:
            c_ret = self._m_db_collection_cases.find({"number": index}, {"_id": 0})
            test_case_row = next(c_ret)
        except StopIteration:
            return None
        rows = self._m_db_collection_steps.find({"test_case_index": index}, {"_id": 0})
        steps = []
        for row in rows:
            data = bytes.fromhex(row["data"])
            # Little hack since BLOB becomes type buffer in py2 and bytes in py3
            # At the end, data will be equivalent types: bytes in py3 and str in py2
            try:
                if isinstance(data, buffer):
                    data = str(data)
            except NameError as e:
                if "buffer" in str(e):  # buffer type does not exist in py3
                    pass
                else:
                    raise
            steps.append(
                data_test_step.DataTestStep(
                    type=row["type"], description=row["description"], data=data, timestamp=row["timestamp"], truncated=row["is_truncated"]
                )
            )
        return data_test_case.DataTestCase(
            name=test_case_row["name"], index=test_case_row["number"], timestamp=test_case_row["timestamp"], steps=steps
        )

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        mydict = {
                "name": name,
                "number": index,
                "timestamp": helpers.get_time_stamp()
                }
        self._m_db_collection_cases.insert_one(mydict)
        self._current_test_case_index = index

    def open_test_step(self, description):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(%d, \'%s\', \'%s\', \'%s\', \'%s\', %d, \'%s\');\n",
                self._current_test_case_index,
                "step",
                description,
                u"",
                helpers.get_time_stamp(),
                0
            ]
        )

    def log_check(self, description):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(%d, \'%s\', \'%s\', \'%s\', \'%s\', %d, \'%s\');\n",
                self._current_test_case_index,
                "check",
                description,
                u"",
                helpers.get_time_stamp(),
                0
            ]
        )

    def log_error(self, description):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(%d, \'%s\', \'%s\', \'%s\', \'%s\', %d, \'%s\');\n",
                self._current_test_case_index,
                "error",
                description,
                u"",
                helpers.get_time_stamp(),
                0
            ]
        )
        self._fail_detected = True
        self._write_log()

    def log_recv(self, data):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(%d, \'%s\', \'%s\', \'%s\', \'%s\', %d, \'%s\');\n",
                self._current_test_case_index,
                "receive",
                u"",
                data.hex(),
                helpers.get_time_stamp(),
                0
            ]
        )

    def log_send(self, data):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(%d, \'%s\', \'%s\', \'%s\', \'%s\', %d, \'%s\');\n",
                self._current_test_case_index,
                "send",
                u"",
                data.hex(),
                helpers.get_time_stamp(),
                0
            ]
        )

    def log_info(self, description):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(%d, \'%s\', \'%s\', \'%s\', \'%s\', %d, \'%s\');\n",
                self._current_test_case_index,
                "info",
                description,
                u"",
                helpers.get_time_stamp(),
                0
            ]
        )

    def log_fail(self, description=""):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(%d, \'%s\', \'%s\', \'%s\', \'%s\', %d, \'%s\');\n",
                self._current_test_case_index,
                "fail",
                description,
                u"",
                helpers.get_time_stamp(),
                0
            ]
        )
        self._fail_detected = True

    def log_pass(self, description=""):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(%d, \'%s\', \'%s\', \'%s\', \'%s\', %d, \'%s\');\n",
                self._current_test_case_index,
                "pass",
                description,
                u"",
                helpers.get_time_stamp(),
                0
            ]
        )

    def Translate(self, s):
        if type(s) == str:
            s = s.replace("\\", "\\\\").replace("\'", "\\\'").replace("\"", "\\\"").replace("\n\n", "\\\n\\\n")\
                .replace("\n", "\\\n").replace("\r\n", "\\\r\\\n").replace("\n", "\\\n").replace("\t", "\\\t")
        return s

    def close_test_case(self):
        self._write_log(force=False)

    def close_test(self):
        self._write_log(force=True)

    def _write_log(self, force=False):
        if len(self._queue) > 0:
            if self._queue_max_len > 0:
                while (
                    self._current_test_case_index - next(x for x in self._queue[0] if isinstance(x, six.integer_types))
                ) >= self._queue_max_len:
                    self._queue.popleft()
            else:
                force = True
            query_list=[]
            if force or self._fail_detected or self._log_first_case:
                for query in self._queue:
                    # abbreviate long entries first
                    if not self._fail_detected:
                        self._truncate_send_recv(query)
                    query_json = {
                    "test_case_index":query[1],
                    "type":query[2],
                    "description":query[3],
                    "data":query[4],
                    "timestamp":query[5],
                    "is_truncated":query[6]
                    }
                    query_list.append(query_json)
                self._m_db_collection_steps.insert_many(query_list)
                query_list.clear()
                self._queue.clear()
                self._log_first_case = False
                self._fail_detected = False

    def _truncate_send_recv(self, query):
        if query[2] in ["send", "recv"] and len(query[4]) > self._data_truncate_length:
            query[6] = 1
            query[4] = query[4][: self._data_truncate_length]


class FuzzLoggerDbReader(object):
    """Read fuzz data saved using FuzzLoggerDb

    Args:
        db_filename (str): Name of database file to read.
    """

    def __init__(self, db_filename):
        self._db_filename = db_filename
        self._db_handler = CommonDBhandler.handler
        self._database_connection = self._db_handler.getCon2()
        if self._database_connection is not None:
            self._db_cursor = self._database_connection.cursor()
        else:
            self._db_cursor = None

        self.collection_name = db_filename
        self._db_handler = CommonDBhandler.handler
        self._m_db = self._db_handler.getMC()['dongjian']
        if self.collection_name+"-cases" in self._m_db.list_collection_names():
            self._m_db_collection_cases = self._m_db[self.collection_name+"-cases"]
        else:
            self._m_db_collection_cases = None
        if self.collection_name+"-steps" in self._m_db.list_collection_names():
            self._m_db_collection_steps = self._m_db[self.collection_name+"-steps"]
        else:
            self._m_db_collection_steps = None

    def get_test_case_data(self, index):
        c = self._db_cursor
        if self._m_db_collection_cases is None or self._m_db_collection_steps is None:
            return ""
        try:
            c_ret = self._m_db_collection_cases.find({"number": index}, {"_id": 0})
            test_case_row = next(c_ret)
        except StopIteration:
            return None
        rows = self._m_db_collection_steps.find({"test_case_index": index}, {"_id": 0})
        steps = []
        for row in rows:
            data = bytes.fromhex(row["data"])
            # Little hack since BLOB becomes type buffer in py2 and bytes in py3
            # At the end, data will be equivalent types: bytes in py3 and str in py2
            try:
                if isinstance(data, buffer):
                    data = str(data)
            except NameError as e:
                if "buffer" in str(e):  # buffer type does not exist in py3
                    pass
                else:
                    raise
            steps.append(
                data_test_step.DataTestStep(
                    type=row["type"], description=row["description"], data=data, timestamp=row["timestamp"],
                    truncated=row["is_truncated"]
                )
            )
        return data_test_case.DataTestCase(
            name=test_case_row["name"], index=test_case_row["number"], timestamp=test_case_row["timestamp"], steps=steps
        )

    def query(self, query, params=None):
        if params is None:
            params = []
        c = self._db_cursor
        if not c:
            return iter([])
        c.execute(query, params)
        return iter(c.fetchall())

    @property
    def failure_map(self):
        c = self._db_cursor
        if not c:
            return ""
        c.execute('SELECT * FROM steps WHERE type=\"fail\" and resultdb=\'%s\'' % self._db_filename)
        failure_steps = iter(c.fetchall())

        failure_map = collections.defaultdict(list)
        for step in failure_steps:
            failure_map[step[0]].append(step[2])
        return failure_map
