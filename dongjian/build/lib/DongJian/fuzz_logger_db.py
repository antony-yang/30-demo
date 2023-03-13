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


class FuzzLoggerDb(ifuzz_logger_backend.IFuzzLoggerBackend):
    """Log fuzz data in a sqlite database file."""

    def __init__(self, db_filename, num_log_cases=0):

        self.db_name = db_filename
        self._db_handler = CommonDBhandler.handler
        self._database_connection = self._db_handler.getCon2()
        self._db_cursor = self._database_connection.cursor()

        self._current_test_case_index = 0

        self._queue = collections.deque([])  # Queue that holds last n test cases before commiting
        self._queue_max_len = num_log_cases
        self._fail_detected = False
        self._log_first_case = True
        self._data_truncate_length = 512

    def get_test_case_data(self, index):
        c = self._db_cursor
        try:
            c.execute("select * from cases where number=%d and resultdb = \"%s\";\n" % (index, self.db_name))
            c_ret = iter(c._rows)
            test_case_row = next(c_ret)
        except StopIteration:
            return None
        c.execute("select * from steps where test_case_index=%d and resultdb = \"%s\";\n" % (index, self.db_name))
        rows = iter(c._rows)
        steps = []
        for row in rows:
            data = bytes.fromhex(row[3])
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
                    type=row[1], description=row[2], data=data, timestamp=row[4], truncated=row[5]
                )
            )
        return data_test_case.DataTestCase(
            name=test_case_row[0], index=test_case_row[1], timestamp=test_case_row[2], steps=steps
        )

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self._queue.append(["INSERT INTO cases VALUES(\'%s\', %d, \'%s\', \'%s\');\n", name, index, helpers.get_time_stamp(), self.db_name])
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
                0,
                self.db_name,
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
                0,
                self.db_name
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
                0,
                self.db_name
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
                0,
                self.db_name
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
                0,
                self.db_name
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
                0,
                self.db_name
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
                0,
                self.db_name
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
                0,
                self.db_name
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

            if force or self._fail_detected or self._log_first_case:
                for query in self._queue:
                    # abbreviate long entries first
                    if not self._fail_detected:
                        self._truncate_send_recv(query)
                    query_tuple = ()
                    for i in range(1, len(query), 1):
                        query_tuple = query_tuple + (self.Translate(query[i]),)
                    # print(query[0] % query_tuple)
                    self._db_cursor.execute(query[0] % query_tuple)
                self._queue.clear()
                self._database_connection.commit()
                self._log_first_case = False
                self._fail_detected = False

    def _truncate_send_recv(self, query):
        if query[2] in ["send", "recv"] and len(query[4]) > self._data_truncate_length:
            query[6] = 1
            #query[4] = buffer(query[4][: self._data_truncate_length])
            query[4] = query[4][: self._data_truncate_length]
            #query[4] = str(base64.b64encode(query[4][: self._data_truncate_length]), encoding="utf-8")


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

    def get_test_case_data(self, index):
        c = self._db_cursor
        if not c:
            return ""
        try:
            c.execute("SELECT * FROM cases WHERE number=%d and resultdb=\'%s\';\n" % (int(index), self._db_filename))
            c_ret = iter(c._rows)
            test_case_row = next(c_ret)
        except StopIteration:
            raise exception.DongJianNoSuchTestCase()

        c.execute("SELECT * FROM steps WHERE test_case_index=%d and resultdb=\'%s\';\n" % (index, self._db_filename))
        rows = iter(c._rows)
        steps = []
        for row in rows:
            data = bytes.fromhex(row[3])
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
                    type=row[1], description=row[2], data=data, timestamp=row[4], truncated=row[5]
                )
            )
        return data_test_case.DataTestCase(
            name=test_case_row[0], index=test_case_row[1], timestamp=test_case_row[2], steps=steps
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
