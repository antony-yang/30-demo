from __future__ import print_function

import os
import subprocess
import sys
import threading
import time
import pykd
import psutil


class DebuggerThreadPykd (threading.Thread):
    def __init__(self, start_commands, process_monitor, proc_name=None, ignore_pid=None, pid=None, log_level=1, **kwargs):
        threading.Thread.__init__(self)
        self.start_commands = start_commands
        self.process_monitor = process_monitor
        self.proc_name = proc_name
        self.ignore_pid = ignore_pid
        self.pid = pid
        self.log_level = log_level

#######################################################

        self.dbg = pykd
        self.finished_starting = threading.Event()
        self.setName("%d" % time.time())
        self.process_monitor.log("debugger thread initialized with UID: %s" % self.getName(), 5)
        self._process = None
        self.access_violation = False

    def log(self, msg="", level=1):
        """
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: str
        @param msg: Message to log
        """

        if self.log_level >= level:
            print("[%s] %s" % (time.strftime("%I:%M.%S"), msg))

    def spawn_target(self):
        self.log("start target process")
        for command in self.start_commands:
            try:
                self._process = subprocess.Popen(command)
            except OSError as e:
                print('OSError "{0}" while starting "{1}"'.format(e.strerror, command), file=sys.stderr)
                raise
        self.log("done. target up and running, giving it 5 seconds to settle in.")
        time.sleep(5)
        self.pid = self._process.pid

    def run(self):
        """
        Main thread routine, called on thread.start(). Thread exits when this routine returns.
        """
        try:
            if len(self.start_commands) > 0 and self.proc_name is not None:
                self.spawn_target()
                self.watch()
            elif len(self.start_commands) > 0:
                self.spawn_target()
            elif self.proc_name is not None:
                self.watch()
            else:
                self.process_monitor.log("error: procmon has no start command or process name to attach to!")
                return False

            self.process_monitor.log("debugger thread-%s attaching to pid: %s" % (self.getName(), self.pid))
            self.dbg.attachProcess(self.pid)
        except pykd.DbgException as e:
            self.process_monitor.log("error: pydbg: {0}".format(str(e).rstrip()))
            self.process_monitor.log("attachProcess error")
            #self.stop_target()
        finally:
            self.finished_starting.set()
        self.dbg.go()
        self.process_monitor.log("debugger thread-%s exiting" % self.getName())
        self.get_exception()
        # exp_handler = ExceptionHandler(self.pid, self.process_monitor)
        # try:
        #     while not exp_handler.is_pause():
        #         self.dbg.go()
        #     self.access_violation = exp_handler.is_pause()
        # except BaseException:
        #     pass

    def get_exception(self):
        self.access_violation = True

        # modules = self.dbg.getModulesList()
        # for i in modules:
        #     self.process_monitor.log(self.dbg.module.name(i))
        # details = self.dbg.dbgCommand("r")
        # self.process_monitor.log(details)
        # modules = details.split('\n')[-3]
        # self.process_monitor.log(modules)
        # self.process_monitor.log(self.dbg.dbgCommand("kv"))
        debugEvent = self.dbg.getLastEvent()
        if debugEvent.type == 0:
            return pykd.eventResult.NoChange
        if debugEvent.type == pykd.eventType.Exception:
            self.process_monitor.crash_bin.record_crash(self.dbg, self.process_monitor.crash_filename, self.process_monitor.test_number)
            self.process_monitor.crash_bin.pydbg = None
            # self.process_monitor.last_synopsis = self.process_monitor.crash_bin.crash_synopsis()
            # first_line = self.process_monitor.last_synopsis.split("\n")[0]
            # self.process_monitor.log("debugger thread-%s caught access violation: '%s'" % (self.getName(), first_line))

            # self.process_monitor.log(pykd.dbgCommand("u"))
            # self.process_monitor.log(pykd.dbgCommand("ub"))
            # os.system("taskkill /F /pid %d" % self.pid)
            self.dbg.killAllProcesses()
            self.process_monitor.log("Sleep 1 second to wait the process end")
            time.sleep(1)
            return pykd.eventResult.NoChange

    def watch(self):
        """
        Continuously loop, watching for the target process. This routine "blocks" until the target process is found.
        Update self.pid when found and return.
        """
        self.process_monitor.log(
            "debugger thread-{0} looking for process name: {1}".format(self.getName(), self.proc_name)
        )
        self.pid = self._scan_proc_names_blocking()
        self.process_monitor.log("debugger thread-{0} match on pid {1}".format(self.getName(), self.pid))

    def _scan_proc_names_blocking(self):
        pid = None
        while pid is None:
            pid = self._scan_proc_names_once()
        return pid

    def _scan_proc_names_once(self):
        for proc in psutil.process_iter():
            if proc.name().lower() == self.proc_name.lower() and proc.pid != self.ignore_pid:
                return proc.pid
        return None

    def stop_target(self):
        try:
            os.system("taskkill /F /pid %d" % self.pid)
            # exit_code = os.system("taskkill /F /pid %d" % self.pid)
            # if exit_code != 0:
            #     os.system("taskkill -F /pid %d" % self.pid)
        except OSError as e:
            print(e.errno)  # TODO interpret some basic errors

    def pre_send(self):
        # un-serialize the crash bin from disk. this ensures we have the latest copy (ie: vmware image is cycling).
        try:
            self.process_monitor.crash_bin.import_file(self.process_monitor.crash_filename)
        except IOError:
            pass  # ignore missing file, etc.
        # pass

    def post_send(self):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        Returns:
            bool: True if the target is still active, False otherwise.
        """
        # av = self.access_violation
        av = self.access_violation

        # if there was an access violation, wait for the debugger thread to finish then kill thread handle.
        # it is important to wait for the debugger thread to finish because it could be taking its sweet ass time
        # uncovering the details of the access violation.
        if av:
            while self.isAlive():
                time.sleep(1)

        # serialize the crash bin to disk.
        self.process_monitor.crash_bin.export_file(self.process_monitor.crash_filename)
        return not av


class ExceptionHandler(pykd.eventHandler):
    def __init__(self , pid, process_monitor):
        pykd.eventHandler.__init__(self)
        self.accessViolationOccured = False
        self.pid = pid
        self.pause = False
        self.process_monitor = process_monitor

    def is_pause(self):
        return self.pause

    def is_continue(self):
        self.pause = False

    def onException(self, exceptInfo):
        # if (exceptInfo.exceptionCode== 0xC0000005):
        #     print(exceptInfo)
        #     print(pykd.dbgCommand("r"))
        #     print(pykd.dbgCommand("kv"))
        #     print(pykd.dbgCommand("u"))
        #     print(pykd.dbgCommand("ub"))
        #     self.pause = True
        #
        #     # pykd.detachProcess(self.pid)
        #     os.system("taskkill /F /pid %d" % self.pid)
        #     print("Sleep 5 second to wait the process end")
        #     time.sleep(5)

        self.pause = True
        self.process_monitor.log(exceptInfo)
        self.process_monitor.log(pykd.dbgCommand("!process"))
        self.process_monitor.log(pykd.dbgCommand("r"))
        self.process_monitor.log(pykd.dbgCommand("kv"))
        self.process_monitor.log(pykd.dbgCommand("u"))
        self.process_monitor.log(pykd.dbgCommand("ub"))


        os.system("taskkill /F /pid %d" % self.pid)
        print("Sleep 5 second to wait the process end")
        time.sleep(1)
        # self.pause = False
        return pykd.eventResult.NoChange


if __name__=="__main__":
    print(pykd.attachProcess(3332,1))
    print(pykd.go())
    pykd.dbgCommand("r")

    #for proc in psutil.process_iter():
    #   if sys.version_info > (3,0):
    #       print(sys.version_info)