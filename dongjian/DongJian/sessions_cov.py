from __future__ import absolute_import, print_function

import datetime
import errno
import copy
import itertools
import logging
import os
import pickle
import time
import traceback
import zlib
from io import open
import signal

import gridfs
import six
import gc

from .sessions import Connection
from .primitives import interesting_values
import threading
import multiprocessing
from .utils import CommonDBhandler
import pickle

from . import (
    blocks,
    constants,
    event_hook,
    exception,
    fuzz_logger,
    fuzz_logger_text,
    fuzz_logger_db_m,
    pgraph,
    primitives,
    coverage,
)
import zipfile

class CovSession(pgraph.Graph):
    """
    Extends pgraph.graph and provides a container for architecting protocol dialogs.

    Args:
        session_filename (str): Filename to serialize persistent data to. Default None.
        index_start (int);      First test case index to run
        index_end (int);        Last test case index to run
        sleep_time (float):     Time in seconds to sleep in between tests. Default 0.
        restart_interval (int): Restart the target after n test cases, disable by setting to 0 (default).
        console_gui (bool):     Use curses to generate a static console screen similar to the webinterface. Has not been
                                tested under Windows. Default False.
        crash_threshold_request (int):  Maximum number of crashes allowed before a request is exhausted. Default 12.
        crash_threshold_element (int):  Maximum number of crashes allowed before an element is exhausted. Default 3.
        restart_sleep_time (int): Time in seconds to sleep when target can't be restarted. Default 5.
        restart_callbacks (list of method): The registered method will be called after a failed post_test_case_callback
                                           Default None.
        pre_send_callbacks (list of method): The registered method will be called prior to each fuzz request.
                                            Default None.
        post_test_case_callbacks (list of method): The registered method will be called after each fuzz test case.
                                                  Default None.
        fuzz_db_keep_only_n_pass_cases (int): Minimize disk usage by only saving passing test cases
                                              if they are in the n test cases preceding a failure or error.
                                              Set to 0 to save after every test case (high disk I/O!). Default 0.
        receive_data_after_each_request (bool): If True, Session will attempt to receive a reply after transmitting
                                                each non-fuzzed node. Default True.
        check_data_received_each_request (bool): If True, Session will verify that some data has
                                                 been received after transmitting each non-fuzzed node, and if not,
                                                 register a failure. If False, this check will not be performed. Default
                                                 False. A receive attempt is still made unless
                                                 receive_data_after_each_request is False.
        receive_data_after_fuzz (bool): If True, Session will attempt to receive a reply after transmitting
                                        a fuzzed message. Default False.
        ignore_connection_reset (bool): Log ECONNRESET errors ("Target connection reset") as "info" instead of
                                failures.
        ignore_connection_aborted (bool): Log ECONNABORTED errors as "info" instead of failures.
        ignore_connection_issues_when_sending_fuzz_data (bool): Ignore fuzz data transmission failures. Default True.
                                This is usually a helpful setting to enable, as targets may drop connections once a
                                message is clearly invalid.
        reuse_target_connection (bool): If True, only use one target connection instead of reconnecting each test case.
                                        Default False.
        target (Target):        Target for fuzz session. Target must be fully initialized. Default None.

        log_level (int):        DEPRECATED Unused. Logger settings are now configured in fuzz_data_logger.
                                Was once used to set the log level.
        logfile (str):          DEPRECATED Unused. Logger settings are now configured in fuzz_data_logger.
                                Was once the name of the log file.
        logfile_level (int):    DEPRECATED Unused. Logger settings are now configured in fuzz_data_logger.
                                Was once used to set the log level for the logfile. Default logger.INFO.
    """

    def __init__(
            self,
            session_filename=None,
            index_start=1,
            index_end=None,
            sleep_time=0.0,
            restart_interval=0,
            console_gui=False,
            crash_threshold_request=12,
            crash_threshold_element=3,
            restart_sleep_time=5,
            restart_callbacks=None,
            pre_send_callbacks=None,
            post_test_case_callbacks=None,
            receive_data_after_each_request=True,
            check_data_received_each_request=False,
            fuzz_db_keep_only_n_pass_cases=0,
            receive_data_after_fuzz=False,
            log_level=logging.INFO,
            logfile=None,
            logfile_level=logging.DEBUG,
            ignore_connection_reset=False,
            ignore_connection_aborted=False,
            ignore_connection_issues_when_sending_fuzz_data=True,
            reuse_target_connection=False,
            target=None,
            enable_cov_mode=True,
            run_id=None,
            queue=None,
            cov_ip="127.0.0.1",
            cov_port=9999,
            script_start=False,
            **kwargs
    ):
        self.enable_cov_mode = enable_cov_mode
        self._ignore_connection_reset = ignore_connection_reset
        self._ignore_connection_aborted = ignore_connection_aborted
        self._ignore_connection_issues_when_sending_fuzz_data = ignore_connection_issues_when_sending_fuzz_data
        self._reuse_target_connection = reuse_target_connection
        _ = log_level
        _ = logfile
        _ = logfile_level

        super(CovSession, self).__init__()

        self.script_start = script_start
        self.session_filename = session_filename
        self._index_start = max(index_start, 1)
        self._index_end = index_end
        self.sleep_time = sleep_time
        self.restart_interval = restart_interval
        self.console_gui = console_gui
        self._crash_threshold_node = crash_threshold_request
        self._crash_threshold_element = crash_threshold_element
        self.restart_sleep_time = restart_sleep_time

        # only support txt logger in this version
        self.fuzz_loggers = []

        self.queue = queue

        if run_id is None:
            self._run_id = datetime.datetime.now().isoformat().replace(":", "-").replace(".", "-")
        else:
            self._run_id = run_id

        if self.script_start:
            self._txt_filename = "script-{0}".format(self._run_id)
        else:
            self._txt_filename = "{0}".format(self._run_id)

        if self.script_start:
            self._db_filename = "script-{0}".format(self._run_id)
        else:
            self._db_filename = "{0}".format(self._run_id)

        if self.script_start:
            self._crash_filename = "script-{0}".format(self._run_id)
        else:
            self._crash_filename = "{0}".format(self._run_id)

        path = os.path.expanduser('~') + "/result/"
        if os.path.exists(path):
            pass
        else:
            os.mkdir(path)

        self.crash_data = []

        self.fuzz_loggers.append(fuzz_logger_text.FuzzLoggerText(file_handle=open(path + self._txt_filename, "w+")))
        self.fuzz_loggers.append(fuzz_logger_text.FuzzLoggerText())

        self._db_logger = fuzz_logger_db_m.FuzzLoggerDbM(
            db_filename=self._db_filename, num_log_cases=fuzz_db_keep_only_n_pass_cases
        )

        self.fuzz_loggers.append(self._db_logger)

        self._fuzz_data_logger = fuzz_logger.FuzzLogger(fuzz_loggers=self.fuzz_loggers)
        self._check_data_received_each_request = check_data_received_each_request
        self._receive_data_after_each_request = receive_data_after_each_request
        self._receive_data_after_fuzz = receive_data_after_fuzz
        self._skip_current_node_after_current_test_case = False
        self._skip_current_element_after_current_test_case = False

        if pre_send_callbacks is None:
            self._pre_send_methods = []
        else:
            self._pre_send_methods = pre_send_callbacks

        if post_test_case_callbacks is None:
            self._post_test_case_methods = []
        else:
            self._post_test_case_methods = post_test_case_callbacks

        if restart_callbacks is None:
            self._restart_methods = []
        else:
            self._restart_methods = restart_callbacks

        self.total_num_mutations = 0
        self.total_mutant_index = 0
        self.fuzz_node = None
        self.targets = []
        self.netmon_results = {}
        self.procmon_results = {}  # map of test case indices to list of crash synopsis strings (failed cases only)
        self.is_paused = False
        self.crashing_primitives = {}
        self.on_failure = event_hook.EventHook()

        # import settings if they exist.
        self.import_file()

        # create a root node. we do this because we need to start fuzzing from a single point and the user may want
        # to specify a number of initial requests.
        self.root = pgraph.Node()
        self.root.name = "__ROOT_NODE__"
        self.root.label = self.root.name
        self.last_recv = None
        self.last_send = None

        self.add_node(self.root)

        if target is not None:
            target.procmon_options["crash_filename"] = self._crash_filename
            try:
                self.add_target(target=target)
            except exception.DongJianRpcError as e:
                self._fuzz_data_logger.log_error(str(e))
                self.finished()
                raise
        ###########################################################

        self.seed_db = CommonDBhandler.handler.getMC()["seed"]
        self.seed_fs = gridfs.GridFS(self.seed_db, collection=self._txt_filename)
        self.total_path = 0
        coverage.set_ip(cov_ip)
        coverage.set_port(cov_port)

    def finished(self):
        self._fuzz_data_logger.log_info("---------------- coverage: " + str(self.total_path) + " ----------------")
        try:
            if self.queue:
                while True:
                    if self.queue.full():
                        time.sleep(2)
                        continue
                    else:
                        self.queue.put(self._run_id)
                        break
        except Exception as e:
            print(e)
        finally:
            if self.script_start:
                self.zip_log("script-" + self._run_id)
            else:
                self.zip_log(self._run_id)


    def zip_log(self, filename):
        zip_info = "zip_log: "
        if filename is not None:
            path = os.path.join(os.path.expanduser('~'), "result")
            if os.path.exists(path):
                pass
            else:
                print(zip_info + "result dir not exists")
            if os.path.exists(path + "/" + filename + ".zip"):
                return
            for root, dirs, files in os.walk(os.path.join(os.path.expanduser('~'), "result")):
                for file in files:
                    rf = os.path.splitext(file)[0]
                    if rf == filename:
                        file_path = os.path.join(os.path.expanduser('~'), "result") + "/" + rf
                        zip = zipfile.ZipFile(file_path + ".zip", "w", zipfile.ZIP_DEFLATED)
                        zip.write(file_path)
                        zip.close()
                        while zipfile.is_zipfile(file_path + ".zip"):
                            if os.path.exists(file_path):
                                os.remove(file_path)
                                print("remove file: " + file_path)
                                break
                            time.sleep(1)
                        break
                break

    def add_node(self, node):
        """
        Add a pgraph node to the graph. We overload this routine to automatically generate and assign an ID whenever a
        node is added.

        Args:
            node (pgraph.Node): Node to add to session graph
        """

        node.number = len(self.nodes)
        node.id = len(self.nodes)

        if node.id not in self.nodes:
            self.nodes[node.id] = node

        return self

    def add_target(self, target):
        """
        Add a target to the session. Multiple targets can be added for parallel fuzzing.

        Args:
            target (Target): Target to add to session
        """

        # pass specified target parameters to the PED-RPC server.
        target.pedrpc_connect()
        target.set_fuzz_data_logger(fuzz_data_logger=self._fuzz_data_logger)

        # add target to internal list.
        self.targets.append(target)

    def connect(self, src, dst=None, callback=None):
        """
        Create a connection between the two requests (nodes) and register an optional callback to process in between
        transmissions of the source and destination request. Leverage this functionality to handle situations such as
        challenge response systems. The session class maintains a top level node that all initial requests must be
        connected to. Example::

            sess = sessions.session()
            sess.connect(sess.root, s_get("HTTP"))

        If given only a single parameter, sess.connect() will default to attaching the supplied node to the root node.
        This is a convenient alias and is identical to the second line from the above example::

            sess.connect(s_get("HTTP"))

        If you register callback method, it must follow this prototype::

            def callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", session
        is a pointer to the session instance which is useful for snagging data such as session.last_recv which contains
        the data returned from the last socket transmission and sock is the live socket. A callback is also useful in
        situations where, for example, the size of the next packet is specified in the first packet. As another
        example, if you need to fill in the dynamic IP address of the target register a callback that snags the IP
        from sock.getpeername()[0].

        Args:
            src (str or Request (pgrah.Node)): Source request name or request node
            dst (str or Request (pgrah.Node), optional): Destination request name or request node
            callback (def, optional): Callback function to pass received data to between node xmits. Default None.

        Returns:
            pgraph.Edge: The edge between the src and dst.
        """

        # if only a source was provided, then make it the destination and set the source to the root node.
        if dst is None:
            dst = src
            src = self.root

        # if source or destination is a name, resolve the actual node.
        if isinstance(src, six.string_types):
            src = self.find_node("name", src)

        if isinstance(dst, six.string_types):
            dst = self.find_node("name", dst)

        # if source or destination is not in the graph, add it.
        if src != self.root and not self.find_node("name", src.name):
            self.add_node(src)

        if self.find_node("name", dst.name) is None:
            self.add_node(dst)

        # create an edge between the two nodes and add it to the graph.
        edge = Connection(src.id, dst.id, callback)
        self.add_edge(edge)

        return edge

    def export_file(self):
        """
        Dump various object values to disk.

        @see: import_file()
        """

        if not self.session_filename:
            return

        data = {
            "session_filename": self.session_filename,
            "index_start": self.total_mutant_index,
            "sleep_time": self.sleep_time,
            "restart_sleep_time": self.restart_sleep_time,
            "restart_interval": self.restart_interval,
            "crash_threshold": self._crash_threshold_node,
            "total_num_mutations": self.total_num_mutations,
            "total_mutant_index": self.total_mutant_index,
            "netmon_results": self.netmon_results,
            "procmon_results": self.procmon_results,
            "is_paused": self.is_paused,
        }

        fh = open(self.session_filename, "wb+")
        fh.write(zlib.compress(pickle.dumps(data, protocol=2)))
        fh.close()

    def feature_check(self):
        """Check all messages/features.

        Returns:
            None
        """
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations()

        self._message_check(self._iterate_messages())

    def fuzz(self, path, target_name, param=[]):
        """Fuzz the entire protocol tree.

        Iterates through and fuzzes all fuzz cases, skipping according to
        self.skip and restarting based on self.restart_interval.

        If you want the web server to be available, your program must persist
        after calling this method. helpers.pause_for_signal() is
        available to this end.

        Returns:
            None
        """
        try:
            # the notes part is threading support, but we don't suggest use thread to achieve this function,
            # there maybe some problems to solve, and it is hard to solve, we don't know why when we use threading,
            # the log file is always incomplete, but when we use process, it is fixed.
            # coverage.setup_shm()
            # coverage.setup_env()
            # self.thread = threading.Thread(target=self.spwan_target, args=[path, target_name, ])
            # self.thread.start()

            # we suggest use the following code to achieve this function, it does not have the log problems.
            # setup these coverage statistic
            coverage.init(self._txt_filename)
            coverage.setup_shm()
            coverage.setup_env()
            coverage.spwan_target(path, target_name, param)

        except Exception as e:
            self._fuzz_data_logger.log_info(str(e))

        """ 
        shm init and setup the target, 
        the following code is used for test only, 
        because it can't monitor the child process
        """

        self._fuzz_data_logger.log_info("===============sleep 5s wait for the share memory setup================")
        self._fuzz_data_logger.log_info("===============----------------------------------------================")
        self._fuzz_data_logger.log_info("===============----------------------------------------================")
        self._fuzz_data_logger.log_info("===============----------------------------------------================")
        self._fuzz_data_logger.log_info("===============----------------------------------------================")
        self._fuzz_data_logger.log_info("===============----------------------------------------================")
        self._fuzz_data_logger.log_info("===============----------------------------------------================")
        self._fuzz_data_logger.log_info("===============----------------------------------------================")

        time.sleep(5)
        #

        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations()

        self._main_fuzz_loop(self._iterate_protocol())
        self._fuzz_data_logger.log_info("---------------- coverage: " + str(self.total_path) + " ----------------")

        if self.enable_cov_mode:
            self._cov_main_fuzz_loop()

    def _message_check(self, fuzz_case_iterator):
        """Check messages for compatibility.

        Preconditions: `self.total_mutant_index` and `self.total_num_mutations` are set properly.

        Args:
            fuzz_case_iterator (Iterable): An iterator that walks through

        Returns:
            None
        """

        try:
            for fuzz_args in fuzz_case_iterator:
                self._check_message(*fuzz_args)
        except KeyboardInterrupt:
            # TODO: should wait for the end of the ongoing test case, and stop gracefully netmon and procmon
            self.export_file()
            self._fuzz_data_logger.log_error("SIGINT received ... exiting")
            raise
        except exception.DongJianRestartFailedError:
            self._fuzz_data_logger.log_error("Restarting the target failed, exiting.")
            self.export_file()
            raise
        except exception.DongJianTargetConnectionFailedError:
            # exception should have already been handled but rethrown in order to escape test run
            pass
        except Exception:
            self._fuzz_data_logger.log_error("Unexpected exception! {0}".format(traceback.format_exc()))
            self.export_file()
            raise

    def _cov_main_fuzz_loop(self):
        try:
            if self._reuse_target_connection:
                self.targets[0].open()

            num_cases_actually_fuzzed = 0

            self._fuzz_data_logger.log_info("===============--------------------================")
            self._fuzz_data_logger.log_info("===============--------------------================")
            self._fuzz_data_logger.log_info("===============--------------------================")
            self._fuzz_data_logger.log_info("=============== start the new fuzz ================")
            self._fuzz_data_logger.log_info("===============--------------------================")
            self._fuzz_data_logger.log_info("===============--------------------================")
            self._fuzz_data_logger.log_info("===============--------------------================")
            self._fuzz_data_logger.log_info("===============--------------------================")

            # infinite mode
            key = 0
            while key < self.total_path:
                self._cov_fuzz_current_case(key)
                num_cases_actually_fuzzed += 1
                key += 1

            if self._reuse_target_connection:
                self.targets[0].close()

        except KeyboardInterrupt:
            # TODO: should wait for the end of the ongoing test case, and stop gracefully netmon and procmon
            self.export_file()
            self._fuzz_data_logger.log_error("SIGINT received ... exiting")
            raise
        except exception.DongJianRestartFailedError:
            self._fuzz_data_logger.log_error("Restarting the target failed, exiting.")
            self.export_file()
            raise
        except exception.DongJianTargetConnectionFailedError:
            # exception should have already been handled but rethrown in order to escape test run
            pass
        except Exception:
            self._fuzz_data_logger.log_error("Unexpected exception! {0}".format(traceback.format_exc()))
            self.export_file()
            raise
        finally:
            coverage.stop_target()
            self.finished()
            self._fuzz_data_logger.close_test()

    def check_failure(self):
        while 1:
            if coverage.check():
                break
            else:
                import json
                import socket
                try:
                    jd = {}
                    for i in range(0, len(self.crash_data)):
                        jd[str(i)] = self.crash_data[i].hex()
                    jdstr = json.dumps(jd)
                    client = socket.socket(socket.AF_INET)
                    client.connect(('127.0.0.1', 1234))
                    client.send(jdstr.encode('utf-8'))
                    client.close()
                except Exception as e:
                    pass
                time.sleep(1)

    def _cov_fuzz_current_case(self, key):
        """
        Fuzzes the current test case. Current test case is controlled by
        fuzz_case_iterator().

        Args:
            path(list of Connection): Path to take to get to the target node.

        """

        target = self.targets[0]

        db_data = None
        ID = None
        if self.seed_fs.exists({"filename": self._txt_filename + '-' + str(key)}):
            ID = self.seed_fs.find_one({"filename": self._txt_filename + '-' + str(key)})._id
            gf = self.seed_fs.get(ID)
            db_data = gf.read()
        if db_data is not None:
            db_data = zlib.decompress(db_data)
            datas = pickle.loads(db_data)
            data: blocks.Request = datas[0]
            data2: primitives.New = datas[1]
            path = datas[2]
            if ID is not None:
                self.seed_fs.delete(ID)
        else:
            return
        path_names = [self.nodes[path[0].src].name]
        for e in path:
            path_names.append(self.nodes[e.dst].name)

        test_path = " -> ".join(path_names)

        self._fuzz_data_logger.open_test_case(
            "CGF MODE: " + "Testing Path is " + test_path,
            "",
            ""
        )

        del db_data, ID, datas, path_names, test_path
        gc.collect()

        if target.procmon:
            self._fuzz_data_logger.open_test_step("Calling procmon pre_send()")
            target.procmon.pre_send(self.total_mutant_index)

        if target.netmon:
            self._fuzz_data_logger.open_test_step("Calling netmon pre_send()")
            target.netmon.pre_send(self.total_mutant_index)

        try:

            total_cov_count = 100
            cov_count = total_cov_count

            while True:

                self.check_failure()

                self._pause_if_pause_flag_is_set()

                self._open_connection_keep_trying(target)

                self._pre_send(target)

                # self.crash_data.clear()

                for e in path[:-1]:
                    node = self.nodes[e.dst]
                    callback_data = self._callback_current_node(node=node, edge=e)
                    self._fuzz_data_logger.open_test_step("Transmit Prep Node '{0}'".format(node.name))
                    self.transmit_normal(target, node, e, callback_data=callback_data)

                data.new_mutate()
                callback_data = self._callback_current_node(node=data, edge=path[-1])
                self._fuzz_data_logger.open_test_step("Fuzzing Node '{0}' using mode 1 ".format(data.name))
                self.transmit_fuzz(target, data, path[-1], callback_data=callback_data)

                if coverage.has_new_bit() > 0:  # AFL MODE
                    self._fuzz_data_logger.log_info("=================== coverage increase 2 ==================")
                    self._fuzz_data_logger.log_info("total_path:" + str(self.total_path))
                    cov_data = copy.deepcopy(data)
                    cov_path = copy.deepcopy(path)
                    cov_data2 = copy.deepcopy(data2)
                    ###########################################################################

                    s = [cov_data, cov_data2, cov_path]
                    dbyte = pickle.dumps(s)
                    dbyte = zlib.compress(dbyte)
                    if not self.seed_fs.exists({"filename": self._txt_filename + '-' + str(self.total_path)}):
                        self.seed_fs.put(dbyte, filename=self._txt_filename + '-' + str(self.total_path))
                    self.total_path += 1

                    del cov_data, cov_data2, cov_path, dbyte
                    gc.collect()
                    ##########################################################################
                    # interesting_values.interesting_bytes.append(data.mutant.render())
                    coverage.set_shm()

                if not self._check_for_passively_detected_failures(target=target):
                    self._post_send(target)
                    self._check_procmon_failures(target=target)
                if not self._reuse_target_connection:
                    target.close()

                if self.sleep_time > 0:
                    self._fuzz_data_logger.open_test_step("Sleep between tests.")
                    self._sleep(self.sleep_time)

                cov_count -= 1
                if cov_count == 0:
                    break

        finally:
            self._process_failures(target=target)
            self._stop_netmon(target=target)
            self._fuzz_data_logger.close_test_case()
            self.export_file()

    def _main_fuzz_loop(self, fuzz_case_iterator):
        """Execute main fuzz logic; takes an iterator of test cases.

        Preconditions: `self.total_mutant_index` and `self.total_num_mutations` are set properly.

        Args:
            fuzz_case_iterator (Iterable): An iterator that walks through fuzz cases.

        Returns:
            None
        """
        normally_exit = False
        try:
            if self._reuse_target_connection:
                self.targets[0].open()
            num_cases_actually_fuzzed = 0
            for fuzz_args in fuzz_case_iterator:
                if self.total_mutant_index < self._index_start:
                    continue
                elif self._index_end is not None and self.total_mutant_index > self._index_end:
                    break

                # Check restart interval
                if (
                        num_cases_actually_fuzzed
                        and self.restart_interval
                        and num_cases_actually_fuzzed % self.restart_interval == 0
                ):
                    self._fuzz_data_logger.open_test_step("restart interval of %d reached" % self.restart_interval)
                    self._restart_target(self.targets[0])

                self._fuzz_current_case(*fuzz_args)
                num_cases_actually_fuzzed += 1

            if self._reuse_target_connection:
                self.targets[0].close()
            normally_exit = True

        except KeyboardInterrupt:
            coverage.stop_target()
            self.finished()
            # TODO: should wait for the end of the ongoing test case, and stop gracefully netmon and procmon
            self.export_file()
            self._fuzz_data_logger.log_error("SIGINT received ... exiting")
            raise
        except exception.DongJianRestartFailedError:
            coverage.stop_target()
            self.finished()
            self._fuzz_data_logger.log_error("Restarting the target failed, exiting.")
            self.export_file()
            raise
        except exception.DongJianTargetConnectionFailedError:
            coverage.stop_target()
            self.finished()
            # exception should have already been handled but rethrown in order to escape test run
            pass
        except Exception:
            coverage.stop_target()
            self.finished()
            self._fuzz_data_logger.log_error("Unexpected exception! {0}".format(traceback.format_exc()))
            self.export_file()
            raise
        finally:
            if not normally_exit:
                coverage.stop_target()
                self.finished()
            self._fuzz_data_logger.close_test()

    def replace_iter(self, rq, iter_dict={}):
        for item in rq.stack:
            if isinstance(item, blocks.Block):
                self.replace_iter(item, iter_dict)
            else:
                if hasattr(item, "mutate_iter"):
                    iter1, = itertools.tee(item.mutate_iter, 1)
                    iter_dict[item] = iter1
                    del item.mutate_iter
        return

    def _fuzz_current_case(self, path):
        """
        Fuzzes the current test case. Current test case is controlled by
        fuzz_case_iterator().

        Args:
            path(list of Connection): Path to take to get to the target node.

        """
        target = self.targets[0]

        self._pause_if_pause_flag_is_set()

        test_case_name = self._test_case_name(path, self.fuzz_node.mutant)

        self._fuzz_data_logger.open_test_case(
            "{0}: {1}".format(self.total_mutant_index, test_case_name),
            name=test_case_name,
            index=self.total_mutant_index,
            num_mutations=self.total_num_mutations,
            current_index=self.fuzz_node.mutant_index,
            current_num_mutations=self.fuzz_node.num_mutations(),
        )

        self._fuzz_data_logger.log_info(
            "Type: %s. Default value: %s. Case %d of %d overall."
            % (
                type(self.fuzz_node.mutant).__name__,
                repr(self.fuzz_node.mutant.original_value),
                self.total_mutant_index,
                self.total_num_mutations,
            )
        )

        if target.procmon:
            self._fuzz_data_logger.open_test_step("Calling procmon pre_send()")
            target.procmon.pre_send(self.total_mutant_index)

        if target.netmon:
            self._fuzz_data_logger.open_test_step("Calling netmon pre_send()")
            target.netmon.pre_send(self.total_mutant_index)

        try:

            self.check_failure()

            self._open_connection_keep_trying(target)

            self._pre_send(target)

            # self.crash_data.clear()

            for e in path[:-1]:
                node = self.nodes[e.dst]
                callback_data = self._callback_current_node(node=node, edge=e)
                self._fuzz_data_logger.open_test_step("Transmit Prep Node '{0}'".format(node.name))
                self.transmit_normal(target, node, e, callback_data=callback_data)

            callback_data = self._callback_current_node(node=self.fuzz_node, edge=path[-1])
            self._fuzz_data_logger.open_test_step("Fuzzing Node '{0}'".format(self.fuzz_node.name))
            self.transmit_fuzz(target, self.fuzz_node, path[-1], callback_data=callback_data)

            # if coverage.has_new_bit(cv_old, cv) == 2: # NEW AFL MODE
            if coverage.has_new_bit() > 0:  # AFL MODE
                self._fuzz_data_logger.log_info("=================== coverage increase 2 ==================")
                self._fuzz_data_logger.log_info("total_path:" + str(self.total_path))

                iter_dict = {}
                self.replace_iter(self.fuzz_node, iter_dict)

                req: blocks.Request = copy.deepcopy(self.fuzz_node)
                # req.original_value = self.fuzz_node
                # req.reset()
                new_req = primitives.New(self.fuzz_node.render(), self.fuzz_node.mutant.render())
                cov_path = copy.deepcopy(path)

                for item in iter_dict.keys():
                    item.mutate_iter = iter_dict[item]
                del iter_dict
                ###########################################################################

                s = [req, new_req, cov_path]
                dbyte = pickle.dumps(s)
                dbyte = zlib.compress(dbyte)
                if not self.seed_fs.exists({"filename": self._txt_filename + '-' + str(self.total_path)}):
                    self.seed_fs.put(dbyte, filename=self._txt_filename + '-' + str(self.total_path))
                self.total_path += 1

                del  req, new_req, cov_path, dbyte
                gc.collect()
                ##########################################################################
                # interesting_values.interesting_bytes.append(self.fuzz_node.mutant.render())
                coverage.set_shm()

            if not self._check_for_passively_detected_failures(target=target):
                self._post_send(target)
                self._check_procmon_failures(target=target)
            if not self._reuse_target_connection:
                target.close()

            if self.sleep_time > 0:
                self._fuzz_data_logger.open_test_step("Sleep between tests.")
                self._sleep(self.sleep_time)
        finally:
            self._process_failures(target=target)
            self._stop_netmon(target=target)
            self._fuzz_data_logger.close_test_case()
            self.export_file()

    def import_file(self):
        """
        Load various object values from disk.

        @see: export_file()
        """
        if self.session_filename is None:
            return

        try:
            with open(self.session_filename, "rb") as f:
                data = pickle.loads(zlib.decompress(f.read()))
        except (IOError, zlib.error, pickle.UnpicklingError):
            return

        # update the skip variable to pick up fuzzing from last test case.
        self._index_start = data["total_mutant_index"]
        self.session_filename = data["session_filename"]
        self.sleep_time = data["sleep_time"]
        self.restart_sleep_time = data["restart_sleep_time"]
        self.restart_interval = data["restart_interval"]
        self._crash_threshold_node = data["crash_threshold"]
        self.total_num_mutations = data["total_num_mutations"]
        self.total_mutant_index = data["total_mutant_index"]
        self.netmon_results = data["netmon_results"]
        self.procmon_results = data["procmon_results"]
        self.is_paused = data["is_paused"]

    # noinspection PyMethodMayBeStatic
    def log(self, msg, level=1):
        raise Exception("Depreciated!")

    def num_mutations(self, this_node=None, path=()):
        """
        Number of total mutations in the graph. The logic of this routine is identical to that of fuzz(). See fuzz()
        for inline comments. The member variable self.total_num_mutations is updated appropriately by this routine.

        Args:
            this_node (request (node)): Current node that is being fuzzed. Default None.
            path (list): Nodes along the path to the current one being fuzzed. Default [].

        Returns:
            int: Total number of mutations in this session.
        """

        if this_node is None:
            this_node = self.root
            self.total_num_mutations = 0

        if isinstance(path, tuple):
            path = list(path)

        for edge in self.edges_from(this_node.id):
            next_node = self.nodes[edge.dst]
            self.total_num_mutations += next_node.num_mutations()

            if edge.src != self.root.id:
                path.append(edge)

            self.num_mutations(next_node, path)

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

        return self.total_num_mutations

    def _pause_if_pause_flag_is_set(self):
        """
        If that pause flag is raised, enter an endless loop until it is lowered.
        """
        while 1:
            if self.is_paused:
                time.sleep(1)
            else:
                break

    def _stop_netmon(self, target):
        if target.netmon:
            captured_bytes = target.netmon.post_send()
            self._fuzz_data_logger.log_info(
                "netmon captured %d bytes for test case #%d" % (captured_bytes, self.total_mutant_index)
            )
            self.netmon_results[self.total_mutant_index] = captured_bytes

    def _check_procmon_failures(self, target):
        """Check for and log any failures from the procmon. Return True if any found.

        Returns:
            bool: True if failures were found. False otherwise.
        """
        if target.procmon:
            self._fuzz_data_logger.open_test_step("Contact process monitor")
            self._fuzz_data_logger.log_check("procmon.post_send()")
            if target.procmon.post_send():
                self._fuzz_data_logger.log_pass("No crash detected.")
            else:
                self._fuzz_data_logger.log_fail(
                    "procmon detected crash on test case #{0}: {1}".format(
                        self.total_mutant_index, target.procmon.get_crash_synopsis()
                    )
                )
                return True
        return False

    def _check_for_passively_detected_failures(self, target):
        """Check for and log passively detected failures. Return True if any found.

        Returns:
            bool: True if falures were found. False otherwise.
        """
        return self._check_procmon_failures(target=target)

    def _process_failures(self, target):
        """Process any failures in self.crash_synopses.

        If self.crash_synopses contains any entries, perform these failure-related actions:
         - log failure summary if needed
         - save failures to self.procmon_results (for website)
         - exhaust node if crash threshold is reached
         - target restart

        Should be called after each fuzz test case.

        Args:
            target (Target): Target to restart if failure occurred.

        Returns:
            bool: True if any failures were found; False otherwise.
        """
        crash_synopses = self._fuzz_data_logger.failed_test_cases.get(self._fuzz_data_logger.all_test_cases[-1], [])
        if len(crash_synopses) > 0:
            self._fuzz_data_logger.open_test_step("Failure summary")

            # retrieve the primitive that caused the crash and increment it's individual crash count.
            self.crashing_primitives[self.fuzz_node.mutant] = self.crashing_primitives.get(self.fuzz_node.mutant, 0) + 1
            self.crashing_primitives[self.fuzz_node] = self.crashing_primitives.get(self.fuzz_node, 0) + 1

            # print crash synopsis
            if len(crash_synopses) > 1:
                # Prepend a header if > 1 failure report, so that they are visible from the main web page
                synopsis = "({0} reports) {1}".format(len(crash_synopses), "\n".join(crash_synopses))
            else:
                synopsis = "\n".join(crash_synopses)
            self.procmon_results[self.total_mutant_index] = crash_synopses
            self._fuzz_data_logger.log_info(synopsis)

            if (
                    self.fuzz_node.mutant is not None
                    and self.crashing_primitives[self.fuzz_node] >= self._crash_threshold_node
            ):
                skipped = self.fuzz_node.num_mutations() - self.fuzz_node.mutant_index
                self._skip_current_node_after_current_test_case = True
                self._fuzz_data_logger.open_test_step(
                    "Crash threshold reached for this request, exhausting {0} mutants.".format(skipped)
                )
                self.total_mutant_index += skipped
                self.fuzz_node.mutant_index += skipped
            elif (
                    self.fuzz_node.mutant is not None
                    and self.crashing_primitives[self.fuzz_node.mutant] >= self._crash_threshold_element
            ):
                if not isinstance(self.fuzz_node.mutant, primitives.Group) and not isinstance(
                        self.fuzz_node.mutant, blocks.Repeat
                ):
                    skipped = self.fuzz_node.mutant.num_mutations() - self.fuzz_node.mutant.mutant_index
                    self._skip_current_element_after_current_test_case = True
                    self._fuzz_data_logger.open_test_step(
                        "Crash threshold reached for this element, exhausting {0} mutants.".format(skipped)
                    )
                    self.total_mutant_index += skipped
                    self.fuzz_node.mutant_index += skipped

            self._restart_target(target)
            return True
        else:
            return False

    def register_post_test_case_callback(self, method):
        """Register a post- test case method.

        The registered method will be called after each fuzz test case.

        Potential uses:
         * Closing down a connection.
         * Checking for expected responses.

        The order of callback events is as follows::

            pre_send() - req - callback ... req - callback - post-test-case-callback

        Args:
            method (function): A method with the same parameters as :func:`~Session.post_send`
            """
        self._post_test_case_methods.append(method)

    # noinspection PyUnusedLocal
    def example_test_case_callback(self, target, fuzz_data_logger, session, *args, **kwargs):
        """
        Example call signature for methods given to :func:`~Session.register_post_test_case_callback`.

        Args:
            target (Target): Target with sock-like interface.
            fuzz_data_logger (ifuzz_logger.IFuzzLogger): Allows logging of test checks and passes/failures.
                Provided with a test case and test step already opened.

            session (Session): Session object calling post_send.
                Useful properties include last_send and last_recv.

            args: Implementations should include \\*args and \\**kwargs for forward-compatibility.
            kwargs: Implementations should include \\*args and \\**kwargs for forward-compatibility.
        """
        # default to doing nothing.
        self._fuzz_data_logger.log_info("No post_send callback registered.")

    # noinspection PyMethodMayBeStatic
    def _pre_send(self, target):
        """
        Execute custom methods to run prior to each fuzz request. The order of events is as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to establish the RPC bind.

        @see: pre_send()

        Args:
            target (session.target): Target we are sending data to
        """

        if len(self._pre_send_methods) > 0:
            try:
                for f in self._pre_send_methods:
                    self._fuzz_data_logger.open_test_step('Pre_Send callback: "{0}"'.format(f.__name__))
                    f(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self, sock=target)
            except Exception:
                self._fuzz_data_logger.log_error(
                    constants.ERR_CALLBACK_FUNC.format(func_name="pre_send") + traceback.format_exc()
                )

    def _restart_target(self, target):
        """
        Restart the fuzz target. If a VMControl is available revert the snapshot, if a process monitor is available
        restart the target process. If custom restart methods are registered, execute them. Otherwise, do nothing.

        Args:
            target (session.target): Target we are restarting

        @raise exception.BoofuzzRestartFailedError if restart fails.
        """

        self._fuzz_data_logger.open_test_step("Restarting target")
        if len(self.on_failure) > 0:
            for f in self.on_failure:
                self._fuzz_data_logger.open_test_step("Calling registered on_failure method")
                f(logger=self._fuzz_data_logger)
        # vm restarting is the preferred method so try that before procmon.
        elif target.vmcontrol:
            self._fuzz_data_logger.log_info("Restarting target virtual machine")
            target.vmcontrol.restart_target()

        # if we have a connected process monitor, restart the target process.
        elif target.procmon:
            self._fuzz_data_logger.log_info("Restarting target process")

            if not target.procmon.restart_target():
                raise exception.DongJianRestartFailedError()

            self._fuzz_data_logger.log_info("Giving the process 3 seconds to settle in")
            time.sleep(3)

        # if we have custom restart methods, execute them
        elif len(self._restart_methods) > 0:
            try:
                for f in self._restart_methods:
                    self._fuzz_data_logger.open_test_step('Target restart callback: "{0}"'.format(f.__name__))
                    f(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self, sock=target)
            except exception.DongJianRestartFailedError:
                raise
            except Exception:
                self._fuzz_data_logger.log_error(
                    constants.ERR_CALLBACK_FUNC.format(func_name="restart_target") + traceback.format_exc()
                )
            finally:
                self._fuzz_data_logger.open_test_step("Cleaning up connections from callbacks")
                target.close()
                if self._reuse_target_connection:
                    self._fuzz_data_logger.open_test_step("Reopening target connection")
                    target.open()

        # otherwise all we can do is wait a while for the target to recover on its own.
        else:
            self._fuzz_data_logger.log_info(
                "No reset handler available... sleeping for {} seconds".format(self.restart_sleep_time)
            )
            time.sleep(self.restart_sleep_time)

        # pass specified target parameters to the PED-RPC server to re-establish connections.
        target.pedrpc_connect()

    def _callback_current_node(self, node, edge):
        """Execute callback preceding current node.

        Returns:
            bytes: Data rendered by current node if any; otherwise None.
        """
        data = None

        # if the edge has a callback, process it. the callback has the option to render the node, modify it and return.
        if edge.callback:
            self._fuzz_data_logger.open_test_step("Callback function")
            data = edge.callback(self.targets[0], self._fuzz_data_logger, session=self, node=node, edge=edge)

        return data

    def transmit_normal(self, sock, node, edge, callback_data):
        """Render and transmit a non-fuzzed node, process callbacks accordingly.

        Args:
            sock (Target, optional): Socket-like object on which to transmit node
            node (pgraph.node.node (Node), optional): Request/Node to transmit
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
            callback_data (bytes): Data from previous callback.
        """
        if callback_data:
            data = callback_data
        else:
            data = node.render()

        # self.crash_data.append(data)

        try:  # send
            self.targets[0].send(data)
            self.last_send = data
        except exception.DongJianTargetConnectionReset:
            # TODO: Switch _ignore_connection_reset for _ignore_transmission_error, or provide retry mechanism
            if self._ignore_connection_reset:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
        except exception.DongJianTargetConnectionAborted as e:
            # TODO: Switch _ignore_connection_aborted for _ignore_transmission_error, or provide retry mechanism
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._ignore_connection_aborted:
                self._fuzz_data_logger.log_info(msg)
            else:
                self._fuzz_data_logger.log_fail(msg)
        try:  # recv
            if self._receive_data_after_each_request:
                self.last_recv = self.targets[0].recv()

                if self._check_data_received_each_request:
                    self._fuzz_data_logger.log_check("Verify some data was received from the target.")
                    if not self.last_recv:
                        # Assume a crash?
                        self._fuzz_data_logger.log_fail("Nothing received from target.")
                    else:
                        self._fuzz_data_logger.log_pass("Some data received from target.")
        except exception.DongJianTargetConnectionReset:
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
        except exception.DongJianTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(msg)
            else:
                self._fuzz_data_logger.log_info(msg)

    def transmit_fuzz(self, sock, node, edge, callback_data):
        """Render and transmit a fuzzed node, process callbacks accordingly.

        Args:
            sock (Target, optional): Socket-like object on which to transmit node
            node (pgraph.node.node (Node), optional): Request/Node to transmit
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
            callback_data (bytes): Data from previous callback.
        """
        if callback_data:
            data = callback_data
        else:
            data = node.render()

        # self.crash_data.append(data)

        try:  # send
            self.targets[0].send(data)
            self.last_send = data
        except exception.DongJianTargetConnectionReset:
            if self._ignore_connection_issues_when_sending_fuzz_data:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
        except exception.DongJianTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._ignore_connection_issues_when_sending_fuzz_data:
                self._fuzz_data_logger.log_info(msg)
            else:
                self._fuzz_data_logger.log_fail(msg)

        try:  # recv
            if self._receive_data_after_fuzz:
                self.last_recv = self.targets[0].recv()
        except exception.DongJianTargetConnectionReset:
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
        except exception.DongJianTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(msg)
            else:
                self._fuzz_data_logger.log_info(msg)
            pass
        return data

    def _iterate_messages(self):
        """Iterates over each message without mutations.

        :raise sex.SullyRuntimeError:
        """
        if not self.targets:
            raise exception.SullyRuntimeError("No targets specified in session")

        if not self.edges_from(self.root.id):
            raise exception.SullyRuntimeError("No requests specified in session")

        self._reset_fuzz_state()

        for x in self._iterate_messages_recursive(this_node=self.root, path=[]):
            yield x

    def _iterate_messages_recursive(self, this_node, path):
        """Recursively iterates over messages. Used by _iterate_messages.

        Args:
            this_node (node.Node): Current node that is being fuzzed.
            path (list of Connection): List of edges along the path to the current one being fuzzed.

        :raise sex.SullyRuntimeError:
        """
        # step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # keep track of the path as we walk through it
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            path.append(edge)

            message_path = "->".join([self.nodes[e.dst].name for e in path])
            logging.debug("checking: {0}".format(message_path))

            self.fuzz_node = self.nodes[path[-1].dst]
            self.total_mutant_index += 1
            yield (path,)

            for x in self._iterate_messages_recursive(self.fuzz_node, path):
                yield x

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

    def _iterate_protocol(self):
        """
        Iterates over fuzz cases and mutates appropriately.
        On each iteration, one may call fuzz_current_case to do the
        actual fuzzing.

        :raise sex.SullyRuntimeError:
        """
        # we can't fuzz if we don't have at least one target and one request.
        if not self.targets:
            raise exception.SullyRuntimeError("No targets specified in session")

        if not self.edges_from(self.root.id):
            raise exception.SullyRuntimeError("No requests specified in session")

        self._reset_fuzz_state()

        for x in self._iterate_protocol_recursive(this_node=self.root, path=[]):
            yield x

    def _iterate_protocol_recursive(self, this_node, path):
        """
        Recursively iterates over fuzz nodes. Used by _fuzz_case_iterator.

        Args:
            this_node (node.Node): Current node that is being fuzzed.
            path (list of Connection): List of edges along the path to the current one being fuzzed.

        :raise sex.SullyRuntimeError:
        """
        # step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # keep track of the path as we fuzz through it, don't count the root node.
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            path.append(edge)

            message_path = "->".join([self.nodes[e.dst].name for e in path])
            logging.debug("fuzzing: {0}".format(message_path))

            for x in self._iterate_single_node(path):
                yield x

            # recursively fuzz the remainder of the nodes in the session graph.
            for x in self._iterate_protocol_recursive(self.fuzz_node, path):
                yield x

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

    def _iterate_single_node(self, path):
        """Iterate fuzz cases for the last node in path.

        Args:
            path (list of Connection): Nodes along the path to the current one being fuzzed.

        Raises:
            sex.SullyRuntimeError:
        """
        # for p in path:
        #     self.fuzz_node = self.nodes[p.dst]
        #     # Loop through and yield all possible mutations of the fuzz node.
        #     # Note: when mutate() returns False, the node has been reverted to the default (valid) state.
        #     while self.fuzz_node.mutate():
        #         self.total_mutant_index += 1
        #         yield (path,)
        #
        #         if self._skip_current_node_after_current_test_case:
        #             self._skip_current_node_after_current_test_case = False
        #             break
        #         elif self._skip_current_element_after_current_test_case:
        #             self._skip_current_element_after_current_test_case = False
        #             self.fuzz_node.skip_element()
        #     self.fuzz_node.reset()
        self.fuzz_node = self.nodes[path[-1].dst]
        # Loop through and yield all possible mutations of the fuzz node.
        # Note: when mutate() returns False, the node has been reverted to the default (valid) state.
        while self.fuzz_node.mutate():
            self.total_mutant_index += 1
            yield (path,)

            if self._skip_current_node_after_current_test_case:
                self._skip_current_node_after_current_test_case = False
                break
            elif self._skip_current_element_after_current_test_case:
                self._skip_current_element_after_current_test_case = False
                self.fuzz_node.skip_element()
        self.fuzz_node.reset()

    def _iterate_single_case_by_index(self, test_case_index):
        fuzz_index = 1
        for fuzz_args in self._iterate_protocol():
            if fuzz_index >= test_case_index:
                self.total_mutant_index = 1
                yield fuzz_args
                break
            fuzz_index += 1

    def _path_names_to_edges(self, node_names):
        """Take a list of node names and return a list of edges describing that path.

        Args:
            node_names (list of str): List of node names describing a path.

        Returns:
            list of Connection: List of edges describing the path in node_names.
        """
        cur_node = self.root
        edge_path = []
        for node_name in node_names:
            next_node = None
            for edge in self.edges_from(cur_node.id):
                if self.nodes[edge.dst].name == node_name:
                    edge_path.append(edge)
                    next_node = self.nodes[edge.dst]
                    break
            if next_node is None:
                raise Exception("No edge found from {0} to {1}".format(cur_node.name, node_name))
            else:
                cur_node = next_node
        return edge_path

    def _check_message(self, path):
        """Sends the current message without fuzzing.

        Current test case is controlled by fuzz_case_iterator().

        Args:
            path(list of Connection): Path to take to get to the target node.

        """
        target = self.targets[0]

        self._pause_if_pause_flag_is_set()

        test_case_name = self._test_case_name_feature_check(path)

        self._fuzz_data_logger.open_test_case(
            "{0}: {1}".format(self.total_mutant_index, test_case_name),
            name=test_case_name,
            index=self.total_mutant_index,
            num_mutations=self.total_num_mutations,
            current_index=self.fuzz_node.mutant_index,
            current_num_mutations=self.fuzz_node.num_mutations(),
        )

        try:
            if target.procmon:
                self._fuzz_data_logger.open_test_step("Calling procmon pre_send()")
                target.procmon.pre_send(self.total_mutant_index)

            if target.netmon:
                self._fuzz_data_logger.open_test_step("Calling netmon pre_send()")
                target.netmon.pre_send(self.total_mutant_index)

            self._open_connection_keep_trying(target)

            self._pre_send(target)

            for e in path[:-1]:
                node = self.nodes[e.dst]
                self._fuzz_data_logger.open_test_step("Prep Node '{0}'".format(node.name))
                callback_data = self._callback_current_node(node=node, edge=e)
                self.transmit_normal(target, node, e, callback_data=callback_data)

            callback_data = self._callback_current_node(node=self.fuzz_node, edge=path[-1])

            self._fuzz_data_logger.open_test_step("Node Under Test '{0}'".format(self.fuzz_node.name))
            self.transmit_normal(target, self.fuzz_node, path[-1], callback_data=callback_data)

            self._post_send(target)
            self._check_procmon_failures(target)
            if not self._reuse_target_connection:
                target.close()

            if self.sleep_time > 0:
                self._fuzz_data_logger.open_test_step("Sleep between tests.")
                self._fuzz_data_logger.log_info("sleeping for %f seconds" % self.sleep_time)
                time.sleep(self.sleep_time)
        finally:
            if self._process_failures(target=target):
                print("FAIL: {0}".format(test_case_name))
            else:
                print("PASS: {0}".format(test_case_name))
            self._stop_netmon(target)
            self._fuzz_data_logger.close_test_case()
            self.export_file()



    def _open_connection_keep_trying(self, target):
        """ Open connection and if it fails, keep retrying.

        Args:
            target (Target): Target to open.
        """
        if not self._reuse_target_connection:
            while True:
                try:
                    target.open()
                    break  # break if no exception
                except exception.DongJianTargetConnectionFailedError:
                    self._fuzz_data_logger.log_info(constants.WARN_CONN_FAILED_TERMINAL)
                    self._restart_target(target)

    def _sleep(self, seconds):
        self._fuzz_data_logger.log_info("sleeping for %f seconds" % seconds)
        time.sleep(seconds)

    def _test_case_name_feature_check(self, path):
        message_path = "->".join([self.nodes[e.dst].name for e in path])
        return "FEATURE-CHECK->{0}".format(message_path)

    def _test_case_name(self, path, mutated_element):
        message_path = "->".join([self.nodes[e.dst].name for e in path])
        if mutated_element.name:
            primitive_under_test = mutated_element.name
        else:
            primitive_under_test = "no-name"
        return "{0}.{1}.{2}".format(message_path, primitive_under_test, self.fuzz_node.mutant_index)

    def _post_send(self, target):
        if len(self._post_test_case_methods) > 0:
            try:
                for f in self._post_test_case_methods:
                    self._fuzz_data_logger.open_test_step('Post- test case callback: "{0}"'.format(f.__name__))
                    f(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self, sock=target)
            except exception.DongJianTargetConnectionReset:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET_FAIL)
            except exception.DongJianTargetConnectionAborted as e:
                self._fuzz_data_logger.log_info(
                    constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
                )
            except exception.DongJianTargetConnectionFailedError:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_FAILED)
            except Exception:
                self._fuzz_data_logger.log_error(
                    constants.ERR_CALLBACK_FUNC.format(func_name="post_send") + traceback.format_exc()
                )
            finally:
                self._fuzz_data_logger.open_test_step("Cleaning up connections from callbacks")

    def _reset_fuzz_state(self):
        """
        Restart the object's fuzz state.

        :return: None
        """
        self.total_mutant_index = 0
        if self.fuzz_node:
            self.fuzz_node.reset()
