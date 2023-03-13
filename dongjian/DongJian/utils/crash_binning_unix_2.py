import json
from io import open
from typing import Type

import pymysql
from past.builtins import xrange
from . import DBhandler
import base64
from . import CommonDBhandler


class CrashBinStruct:
    def __init__(self):
        self.exception_module = None
        self.exception_address = 0
        self.exception_code = None
        self.write_violation = 0
        self.violation_address = 0
        self.violation_thread_id = 0
        self.context = None
        self.context_dump = None
        self.disasm = None
        self.disasm_around = []
        self.stack_unwind = []
        self.seh_unwind = []
        self.extra = None


class CrashBinningUnix:
    """
    @todo: Add MySQL import/export.
    """
    crashbinstruct = CrashBinStruct()
    bins = {}
    last_crash = None
    pydbg = None



    def __init__(self):
        self.bins = {}
        self.last_crash = None
        self.pydbg = None
        #self._db_handler = DBhandler.dbhandler()
        self._db_handler = CommonDBhandler.handler
        self._db_connection = None
        self._db_cursor = None

    # def record_crash(self, pydbg, extra=None):
    #     """
    #     Given a PyDbg instantiation that at the current time is assumed to have "crashed" (access violation for example)
    #     record various details such as the disassemly around the violating address, the ID of the offending thread, the
    #     call stack and the SEH unwind. Store the recorded data in an internal dictionary, binning them by the exception
    #     address.
    #
    #     @type  pydbg: pydbg
    #     @param pydbg: Instance of pydbg
    #     @type  extra: Mixed
    #     @param extra: (Optional, Def=None) Whatever extra data you want to store with this bin
    #     """
    #
    #     self.pydbg = pydbg
    #     crash = CrashBinStruct()
    #
    #     # add module name to the exception address.
    #     exception_module = pydbg.addr_to_module(pydbg.dbg.u.Exception.ExceptionRecord.ExceptionAddress)
    #
    #     if exception_module:
    #         exception_module = exception_module.szModule
    #     else:
    #         exception_module = "[INVALID]"
    #
    #     crash.exception_module = exception_module
    #     crash.exception_address = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionAddress
    #     crash.write_violation = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
    #     crash.violation_address = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]
    #     crash.violation_thread_id = pydbg.dbg.dwThreadId
    #     crash.context = pydbg.context
    #     crash.context_dump = pydbg.dump_context(pydbg.context, print_dots=False)
    #     crash.disasm = pydbg.disasm(crash.exception_address)
    #     crash.disasm_around = pydbg.disasm_around(crash.exception_address, 10)
    #     crash.stack_unwind = pydbg.stack_unwind()
    #     crash.seh_unwind = pydbg.seh_unwind()
    #     crash.extra = extra
    #
    #     # add module names to the stack unwind.
    #     for i in xrange(len(crash.stack_unwind)):
    #         addr = crash.stack_unwind[i]
    #         module = pydbg.addr_to_module(addr)
    #
    #         if module:
    #             module = module.szModule
    #         else:
    #             module = "[INVALID]"
    #
    #         crash.stack_unwind[i] = "%s:%08x" % (module, addr)
    #
    #     # add module names to the SEH unwind.
    #     for i in xrange(len(crash.seh_unwind)):
    #         (addr, handler) = crash.seh_unwind[i]
    #
    #         module = pydbg.addr_to_module(handler)
    #
    #         if module:
    #             module = module.szModule
    #         else:
    #             module = "[INVALID]"
    #
    #         crash.seh_unwind[i] = (addr, handler, "%s:%08x" % (module, handler))
    #
    #     if crash.exception_address not in self.bins:
    #         self.bins[crash.exception_address] = []
    #
    #     self.bins[crash.exception_address].append(crash)
    #     self.last_crash = crash

    def record_crash(self, crashinfo, extra=None):
        """
        Given a PyDbg instantiation that at the current time is assumed to have "crashed" (access violation for example)
        record various details such as the disassemly around the violating address, the ID of the offending thread, the
        call stack and the SEH unwind. Store the recorded data in an internal dictionary, binning them by the exception
        address.

        @type  pydbg: pydbg
        @param pydbg: Instance of pydbg
        @type  extra: Mixed
        @param extra: (Optional, Def=None) Whatever extra data you want to store with this bin
        """

        #no need
        self.pydbg = None

        if crashinfo.exception_address not in self.bins:
            self.bins[crashinfo.exception_address] = []

        self.bins[crashinfo.exception_address].append(crashinfo)
        self.last_crash = crashinfo

    # @property
    # def __class__(self: _T) -> Type[_T]:
    #     return super().__class__()

    def crash_synopsis(self, crash=None):
        """
        For the supplied crash, generate and return a report containing the disassemly around the violating address,
        the ID of the offending thread, the call stack and the SEH unwind. If not crash is specified, then call through
        to last_crash_synopsis() which returns the same information for the last recorded crash.

        @see: crash_synopsis()

        @type  crash: CrashBinStruct
        @param crash: (Optional, def=None) Crash object to generate report on

        @rtype:  str
        @return: Crash report
        """

        if not crash:
            return self.last_crash_synopsis()

        if crash.write_violation:
            direction = "write to"
        else:
            direction = "read from"

        synopsis = "%s:%08x %s from thread %d caused access violation\nwhen attempting to %s 0x%08x\n\n" % (
            crash.exception_module,
            crash.exception_address,
            crash.disasm,
            crash.violation_thread_id,
            direction,
            crash.violation_address,
        )

        synopsis += crash.context_dump

        synopsis += "\ndisasm around:\n"
        for (ea, inst) in crash.disasm_around:
            synopsis += "\t0x%08x %s\n" % (ea, inst)

        if len(crash.stack_unwind):
            synopsis += "\nstack unwind:\n"
            for entry in crash.stack_unwind:
                synopsis += "\t%s\n" % entry

        if len(crash.seh_unwind):
            synopsis += "\nSEH unwind:\n"
            for (addr, handler, handler_str) in crash.seh_unwind:
                synopsis += "\t%08x -> %s\n" % (addr, handler_str)

        return synopsis + "\n"

    def handle_class(self, o):
        if type(o) == bytes:
            pass
        else:
            return o.__dict__

    def export_file(self, file_name, crashinfo):
        """
        Dump the entire object structure to disk.

        @see: import_file()

        @type  file_name:   str
        @param file_name:   File name to export to

        @rtype:             CrashBinning
        @return:            self
        """
        # null out what we don't serialize but save copies to restore after dumping to disk.
        bins={}
        if crashinfo.exception_address not in self.bins:
            bins[crashinfo.exception_address] = []

        bins[crashinfo.exception_address].append(crashinfo)
        self.last_crash = crashinfo

        last_crash = self.last_crash
        pydbg = self.pydbg

        self.last_crash = self.pydbg = None

        json.dump(bins, open(file_name, "w+"), default=self.handle_class)   #default=lambda o: o.__dict__


        #############################    joshwoo added
        try:
            self._db_connection = self._db_handler.getCon2()
            self._db_cursor = self._db_connection.cursor()
            if len(self.bins) > 0:
                db_str = json.dumps(self.bins, default=self.handle_class)
                self._db_cursor.execute("insert into crash_bin values(%d ,\'%s\', \'%s\');\n" % (0, db_str, file_name))
                self._db_connection.commit()
        except Exception as e:
            print("crash_bin export_file: \n" + str(e))
        ###############################

        self.last_crash = last_crash
        self.pydbg = pydbg

        return self

    def import_file(self, file_name):
        """
        Load the entire object structure from disk.

        @see: export_file()

        @type  file_name:   str
        @param file_name:   File name to import from

        @rtype:             CrashBinning
        @return:            self
        """

        self.bins = {}
        bin_dict = json.load(open(file_name, "rb"))
        for (crash_address, bin_list) in bin_dict.items():
            self.bins[crash_address] = []
            for single_bin in bin_list:
                tmp = CrashBinStruct()
                tmp.__dict__ = single_bin
                self.bins[crash_address].append(tmp)

        return self

    def last_crash_synopsis(self):
        """
        For the last recorded crash, generate and return a report containing the disassemly around the violating
        address, the ID of the offending thread, the call stack and the SEH unwind.

        @see: crash_synopsis()

        @rtype:  String
        @return: Crash report
        """

        if self.last_crash.write_violation:
            direction = "write to"
        else:
            direction = "read from"

        synopsis = "%s:%08x %s from thread %d caused access violation\nwhen attempting to %s 0x%08x\n\n" % (
            self.last_crash.exception_module,
            self.last_crash.exception_address,
            self.last_crash.disasm,
            self.last_crash.violation_thread_id,
            direction,
            self.last_crash.violation_address,
        )

        synopsis += self.last_crash.context_dump

        synopsis += "\ndisasm around:\n"
        for (ea, inst) in self.last_crash.disasm_around:
            synopsis += "\t0x%08x %s\n" % (ea, inst)

        if len(self.last_crash.stack_unwind):
            synopsis += "\nstack unwind:\n"
            for entry in self.last_crash.stack_unwind:
                synopsis += "\t%s\n" % entry

        if len(self.last_crash.seh_unwind):
            synopsis += "\nSEH unwind:\n"
            for (addr, handler, handler_str) in self.last_crash.seh_unwind:
                try:
                    disasm = self.pydbg.disasm(handler)
                except Exception:
                    disasm = "[INVALID]"

                synopsis += "\t%08x -> %s %s\n" % (addr, handler_str, disasm)

        return synopsis + "\n"
