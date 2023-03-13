from __future__ import print_function

import pymysql
from pygdbmi.gdbcontroller import GdbController
import os
import json

try:
    import resource  # Linux only

    resource.setrlimit(  # Equivalent to: ulimit -c unlimited
        resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
    )
except ImportError:
    pass
import signal
import subprocess
import sys
import threading
import time

import psutil
from io import open

if not getattr(__builtins__, "WindowsError", None):
    class WindowsError(OSError):
        """Mock WindowsError since Linux Python lacks WindowsError"""

        @property
        def winerror(self):
            return self.errno

        pass


def _enumerate_processes():
    for pid in psutil.pids():
        yield (pid, psutil.Process(pid).name())


def _get_coredump_path():
    """
    This method returns the path to the coredump file if one was created
    """
    if sys.platform == "linux" or sys.platform == "linux2":
        path = "./core"
        if os.path.isfile(path):
            return path

    return None


class DebuggerThreadUnix(threading.Thread):
    def __init__(
            self, start_commands, process_monitor, proc_name=None, ignore_pid=None, coredump_dir=None, log_level=1,
            **kwargs
    ):
        """
        This class isn't actually ran as a thread, only the start_monitoring
        method is. It can spawn/stop a process, wait for it to exit and report on
        the exit status/code.
        """
        threading.Thread.__init__(self)
        self.process_monitor = process_monitor
        self.process_monitor.mutex.acquire()

        self.proc_name = proc_name
        self.ignore_pid = ignore_pid
        self.start_commands = start_commands
        self.coredump_dir = coredump_dir
        self.finished_starting = threading.Event()
        # if isinstance(start_commands, basestring):
        #     self.tokens = start_commands.split(' ')
        # else:
        #     self.tokens = start_commands
        self.cmd_args = []
        self.pid = None
        self.exit_status = None
        self.log_level = log_level
        self._process = None
        self.bug = False
        self.process_monitor.mutex.release()

    def log(self, msg="", level=1):
        """
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: str
        @param msg: Message to log
        """

        if self.log_level >= level:
            print("[%s] %s" % (time.strftime("%I:%M.%S"), msg))

    def spawn_target(self):
        self.log("starting target process")

        for command in self.start_commands:
            try:
                self._process = subprocess.Popen(command)
            except WindowsError as e:
                print(
                    'WindowsError {errno}: "{strerror} while starting "{cmd}"'.format(
                        errno=e.winerror, strerror=e.strerror, cmd=command
                    ),
                    file=sys.stderr,
                )
                return False
            except OSError as e:
                print(
                    'OSError {errno}: "{strerror} while starting "{cmd}"'.format(
                        errno=e.errno, strerror=e.strerror, cmd=command
                    ),
                    file=sys.stderr,
                )
                return False
        if self.proc_name:
            self.log("done. waiting for start command to terminate.")
            os.waitpid(self._process.pid, 0)
            self.log('searching for process by name "{0}"'.format(self.proc_name))
            self.watch()
            self._psutil_proc = psutil.Process(pid=self.pid)
            self.process_monitor.log("found match on pid %d".format(self.pid))
        else:
            self.log("done. target up and running, giving it 5 seconds to settle in.")
            time.sleep(5)
            self.pid = self._process.pid
        self.process_monitor.log("attached to pid: {0}".format(self.pid))

    def run(self):
        """
        self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        while self.exit_status == (0, 0):
            self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        """
        self.process_monitor.mutex.acquire()
        if len(self.start_commands) > 0:
            self.spawn_target()
            self.finished_starting.set()
            if self.proc_name:
                gone, _ = psutil.wait_procs([self._psutil_proc])
                while True:
                    if not self._psutil_proc.is_running():
                        self.bug = True
                        break
                    time.sleep(1)
                self.exit_status = gone[0].returncode
            else:
                self._psutil_proc = psutil.Process(pid=self.pid)
                exit_info = os.waitpid(self.pid, 0)
                while True:
                    if not self._psutil_proc.is_running():
                        self.bug = True
                        break
                    time.sleep(1)
                self.exit_status = exit_info[1]  # [0] is the pid
        else:
            if self.proc_name:
                self.watch()
                gone, _ = psutil.wait_procs([psutil.Process(pid=self.pid)])
                while True:
                    if not self._psutil_proc.is_running():
                        self.bug = True
                        break
                    time.sleep(1)
                self.exit_status = gone[0].returncode
            else:
                self.process_monitor.log("no start_commands or proc_name")

        default_reason = "Process died for unknown reason"
        if self.exit_status is not None:
            if os.WCOREDUMP(self.exit_status):
                reason = "Segmentation fault"
                self.stop_target()
                while self._psutil_proc.is_running():
                    time.sleep(0.1)
                self.get_exception()
            elif os.WIFSTOPPED(self.exit_status):
                reason = "Stopped with signal " + str(os.WTERMSIG(self.exit_status))
            elif os.WIFSIGNALED(self.exit_status):
                reason = "Terminated with signal " + str(os.WTERMSIG(self.exit_status))
            elif os.WIFEXITED(self.exit_status):
                reason = "Exit with code - " + str(os.WEXITSTATUS(self.exit_status))
            else:
                reason = default_reason
        else:
            reason = default_reason
        print("sssssssssssssssssssssssssssssssss")
        self.process_monitor.last_synopsis = "[{0}] Crash. Exit code: {1}. Reason - {2}\n".format(
            time.strftime("%I:%M.%S"), self.exit_status if self.exit_status is not None else "<unknown>", reason
        )
        self.process_monitor.mutex.release()

    def watch(self):
        """
        Continuously loop, watching for the target process. This routine "blocks" until the target process is found.
        Update self.pid when found and return.
        """
        self.pid = None
        while not self.pid:
            for (pid, name) in _enumerate_processes():
                # ignore the optionally specified PID.
                if pid == self.ignore_pid:
                    continue

                if name.lower() == self.proc_name.lower():
                    self.pid = pid
                    break

    def get_exit_status(self):
        return self.exit_status

    def stop_target(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError as e:
            print(e.errno)  # TODO interpret some basic errors

    def get_exception(self):
        with open(self.process_monitor.crash_filename, "a") as rec_file:
            rec_file.write(self.process_monitor.last_synopsis.encode().decode())

        if self.process_monitor.coredump_dir is not None:
            dest = os.path.join(self.process_monitor.coredump_dir, str(self.process_monitor.test_number))
            src = _get_coredump_path()

            if src is not None:
                self.bug = True

                self.log("moving core dump %s -> %s" % (src, dest))
                os.rename(src, dest)

                class CrashBinStruct:
                    def __init__(self):
                        self.exception_module = None  # dll or exe name  only windows
                        self.exception_address = 0  # exp addr
                        self.exception_code = None  # exp err code   only windows
                        self.write_violation = 0  # 0,1,8 0:write_violation 1:address_invalid 8:PEB   only windows
                        self.violation_address = 0  # violation_address,uaually seems to exp addr    only windows
                        self.violation_thread_id = 0  # violation thread id
                        self.context = None  # None
                        self.context_dump = None  # register
                        self.disasm = None  # up down content 1 line
                        self.disasm_around = []  # up down content 10 lines
                        self.stack_unwind = []  # backtrace
                        self.seh_unwind = []  # seh info,only Windows
                        self.extra = None  # case number

                exportinfo = CrashBinStruct()
                exportinfo.exception_module = None
                exportinfo.exception_code = None
                exportinfo.write_violation = 0
                exportinfo.violation_address = 0
                exportinfo.context = 0
                exportinfo.seh_unwind = []
                exportinfo.extra = self.process_monitor.test_number

                # parse GDB response
                # execfile = 'exec-file ' + self.start_commands[0]
                corefile = 'core-file ' + dest
                gdbmi = GdbController()
                # gdbmi.write(execfile)
                gdbmi.write(corefile)
                text = []
                responses = gdbmi.write('bt')
                # print(responses)
                for response in responses:
                    print(json.dumps(response))
                    if (response['type'] == "console"):
                        # text.append(
                        #     response['payload'].replace("\\\\", '\\').replace("\\t", "\t").replace("\\n", "\n").replace(
                        #         "\\\"", "\""))
                        text.append(response['payload'])
                exportinfo.exception_address = text[0].split(" ")[2]

                text = []
                responses = gdbmi.write('i thread')
                for response in responses:
                    if (response['type'] == "console"):
                        # text.append(
                        #     response['payload'].replace("\\\\", '\\').replace("\\t", "\t").replace("\\n", "\n").replace(
                        #         "\\\"", "\""))
                        text.append(response['payload'])
                exportinfo.violation_thread_id = text[1].split(" ")[6]

                text = []
                regstr = ''
                responses = gdbmi.write('i r')
                for response in responses:
                    if (response['type'] == "console"):
                        regstr += response['payload']
                regstr = regstr.replace("\\t", " ")
                exportinfo.context_dump = regstr.split("\\n")

                text = []
                responses = gdbmi.write('x /i' + exportinfo.exception_address)
                for response in responses:
                    if (response['type'] == "console"):
                        text.append(
                            response['payload'].replace("\\\\", '\\').replace("\\t", "\t").replace("\\n", "\n").replace("\\\"", "\""))
                        #text.append(response['payload'])
                exportinfo.disasm = text[0]

                gdbmi.exit()

                execfile = 'exec-file ' + self.start_commands[0]
                corefile = 'core-file ' + dest
                gdbmidetail = GdbController()
                gdbmidetail.write(execfile)
                gdbmidetail.write(corefile)

                text = []
                btstr = ''
                responses = gdbmidetail.write('bt')
                # print(responses)
                for response in responses:
                    print(json.dumps(response))
                    if (response['type'] == "console"):
                        text.append(
                            response['payload'].replace("\\\\", '\\').replace("\\t", "\t").replace("\\n", "\n").replace(
                                "\\\"", "\"").replace("\n","").replace("\t"," "))
                        #btstr += response['payload']
                #exportinfo.stack_unwind = btstr.split("\\n")
                exportinfo.stack_unwind = text

                text = []
                responses = gdbmidetail.write('disassemble')
                for response in responses:
                    if (response['type'] == "console"):
                        text.append(
                            response['payload'].replace("\\\\", '\\').replace("\\t", "\t").replace("\\n", "\n").replace(
                                "\\\"", "\"").replace("\n","").replace("\t"," "))
                        #text.append(response['payload'])
                exportinfo.disasm_around = text

                gdbmidetail.exit()
                # self.process_monitor.crash_bin_unix.record_crash(self.process_monitor.crash_bin_unix.crashbinstruct)
                self.process_monitor.crash_bin_unix.export_file(self.process_monitor.crash_filename, exportinfo)

    def pre_send(self):
        pass

    def post_send(self):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        Returns:
            bool: True if the target is still active, False otherwise.
        """
        # if self.bug:
        #     for i in range(0, 20):
        #         if self._psutil_proc.is_running():
        #             time.sleep(0.1)
        #         else:
        #             self.process_monitor.mutex.acquire()
        #             if self._psutil_proc.is_running():
        #                 self.process_monitor.mutex.release()
        #                 return not self.bug
        #             else:
        #                 print("get_exp!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        #                 self.get_exception()
        #             self.process_monitor.mutex.release()
        #             break
        # return not self.bug

        for i in range(0, 20):
            if self._psutil_proc.is_running():
                time.sleep(0.05)
            else:
                self.process_monitor.mutex.acquire()
                if self._psutil_proc.is_running():
                    self.process_monitor.mutex.release()
                    return not self.bug
                else:
                    print("get_exp!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                    # self.get_exception()
                self.process_monitor.mutex.release()
                break
        return not self.bug


