from DongJian import *

param = {
	"param": {
		"dport": {
			"ness": 0,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 502
		},
		"proc_name": {
			"ness": 0,
			"default": ""
		},
		"target_ip": {
			"ness": 1,
			"default": "127.0.0.1"
		},
		"start_cmds": {
			"ness": 0,
			"default": []
		}
	},
	"proto": "Modbus_tcp"
}


def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    session = Session(
        target=Target(
            connection=SocketConnection(target_ip, pport, proto='tcp')),
        **kwargs
    )

    s_initialize("read_coil_memory")
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0000, name='protoId', fuzzable=False)
        s_word(0x03, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('read_coil_memory_block'):
            s_byte(0x81, name='funcCode read coil memory')
            s_byte(0x02, name="test")
            # s_word(0x0000, name='start address')
            # s_word(0x0000, name='quantity')
            s_block_end('read_coil_memory_block')
    s_block_end('modbus_head')
    s_repeat("modbus_head", min_reps=1, max_reps=255)

    # ---------------------------------------

    s_initialize('read_holding_registers')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('read_holding_registers_block'):
            s_byte(0x01, name='read_holding_registers')
            s_word(0x0000, name='start address')
            s_word(0x0000, name='quantity')
        s_block_end('read_holding_registers_block')
    s_block_end("modbus_head")

    # ---------------------------------------

    s_initialize('ReadDiscreteInputs')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('ReadDiscreteInputsRequest'):
            s_byte(0x02, name='funcCode', fuzzable=False)
            s_word(0x0000, name='start_address')
            s_word(0x0000, name='quantity')
        s_block_end('ReadDiscreteInputsRequest')
    s_block_end("ReadDiscreteInputs")

    # ----------------------------------------
    s_initialize('ReadHoldingRegisters')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('ReadHoldingRegistersRequest'):
            s_byte(0x03, name='funcCode', fuzzable=False)
            s_word(0x0000, name='start_address')
            s_word(0x0000, name='quantity')
        s_block_end('ReadHoldingRegistersRequest')
    s_block_end("ReadHoldingRegisters")

    # ----------------------------------------
    s_initialize('ReadInputRegisters')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('ReadInputRegistersRequest'):
            s_byte(0x04, name='funcCode', fuzzable=False)
            s_word(0x0000, name='start_address')
            s_word(0x0000, name='quantity')
        s_block_end('ReadHoldingRegistersRequest')
    s_block_end("ReadHoldingRegisters")

    # ------------------------------------------
    s_initialize('WriteSingleCoil')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('WriteSingleCoilRequest'):
            s_byte(0x05, name='funcCode', fuzzable=False)
            s_word(0x0000, name='start_address')
            s_word(0x0000, name='quantity')
        s_block_end('WriteSingleCoilRequest')
    s_block_end("WriteSingleCoil")

    # ------------------------------------------
    s_initialize('WriteSingleRegister')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('WriteSingleRegisterRequest'):
            s_byte(0x06, name='funcCode', fuzzable=False)
            s_word(0x0000, name='output_address')
            s_word(0x0000, name='output_value')
        s_block_end('WriteSingleCoilRequest')
    s_block_end("WriteSingleRegister")

    # ------------------------------------------

    s_initialize('ReadExceptionStatus')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('ReadExceptionStatusRequest'):
            s_byte(0x07, name='funcCode', fuzzable=False)
        s_block_end('ReadExceptionStatusRequest')
    s_block_end("ReadExceptionStatus")

    # -----------------------------------------

    s_initialize('ReadExceptionStatusError')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('ReadExceptionStatusErrorRequest'):
            s_byte(0x87, name='funcCode', fuzzable=False)
        # ----------------------------------------
        s_block_end('ReadExceptionStatusErrorRequest')
    s_block_end("ReadExceptionStatusError")

    # ---------------------------------------

    s_initialize('WriteMultipleCoils')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('WriteMultipleCoilsRequest'):
            s_byte(0x0f, name='func_code', fuzzable=False)
            s_word(0x0000, name='starting_address')
            s_dword(0x0000, name='byte_count')
            s_size("outputsValue", length=8)
            if s_block_start("outputsValue"):
                s_word(0x00, name='outputsValue1')
                s_block_end()
            s_block_end()
        s_block_end()

    # ------------------------------------------------------

    s_initialize('WriteMultipleRegisters')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('WriteMultipleRegistersRequest'):
            s_byte(0x10, name='func_code', fuzzable=False)
            s_word(0x0000, name='starting_address')
            s_dword(0x0000, name='byte_count')
            s_size("outputsValue", length=16)
            s_size("outputsValue", length=8)
            if s_block_start("outputsValue"):
                s_dword(0x0000, name='outputsValue1')
            s_block_end()
        s_block_end()
    s_block_end()

    # -----------------------------------------

    s_initialize('ReportSlaveId')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('ReportSlaveIdRequest'):
            s_byte(0x11, name='func_code', fuzzable=False)
        s_block_end()
    s_block_end()

    # -----------------------------------------

    s_initialize('ReadFileSub')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('ReadFileSubRequest'):
            s_byte(0x06, name='refType', fuzzable=False)
            s_word(0x0001, name='fileNumber')
            s_word(0x0000, name='recordNumber')
            s_word(0x0000, name='recordLength')
        s_block_end()
    s_block_end()

    # -----------------------------------------
    s_initialize('ReadFileRecord')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('ReadFileRecordRequest'):
            s_byte(0x14, name='funcCode', fuzzable=False)
            s_byte(0x0001, name='byteCount')
        s_block_end()
    s_block_end()

    # -----------------------------------------

    s_initialize('WriteFileSub')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('WriteFileSubRequest'):
            s_byte(0x06, name='refType', fuzzable=False)
            s_word(0x0001, name='fileNumber')
            s_word(0x0000, name='recordNumber')
            # ---------------------------------
            # s_size is record
            s_size('recordData', length=16)
            if s_block_start("recordDataBlock"):
                s_word(0x0000, name='recordData')
            s_word(0x0000, name='recordLength')
        s_block_end()
    s_block_end()

    # ------------------------------------------

    s_initialize('WriteFileRecord')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('WriteFileRecordRequest'):
            s_byte(0x15, name='funcCode', fuzzable=False)
            s_byte(0x00, name='datalength')
        # add payload ,random charactic
        s_block_end()
    s_block_end()

    # -------------------------------------------

    s_initialize('MaskWriteRegister')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('MaskWriteRegisterRequest'):
            s_byte(0x96, name='funcCode', fuzzable=False)
            s_word(0x0000, name='refAddr')
            s_word(0xffff, name='andMask')
            s_word(0x0000, name='orMask')
        # add payload ,random charactic
        s_block_end()
    s_block_end()

    # -------------------------------------------

    s_initialize('ReadWriteMultipleRegisters')
    if s_block_start("modbus_head"):
        s_word(0x0001, name='transId', fuzzable=True)
        s_word(0x0002, name='protoId', fuzzable=False)
        s_word(0x06, name='length')
        s_byte(0xff, name='unit Identifier', fuzzable=False)
        if s_block_start('ReadWriteMultipleRegistersRequest'):
            s_byte(0x17, name='funcCode', fuzzable=False)
            s_word(0x0000, name='readStartingAddr')
            s_word(0x0001, name='readQuantityRegisters')
            s_word(0x0000, name='writeStartingAddr')
            s_size('writeQuantityRegisters1', length=16, endian='>', name="writeQuantityRegisters")
            s_size('writeQuantityRegisters1', length=8, endian='>', name="byteCount", math=lambda x: 2 * x)
            if s_block_start('writeQuantityRegisters1'):
                s_size('modbus_head', length=2)
            s_block_end()
        s_block_end()
    s_block_end()

    session.connect(s_get("read_coil_memory"))
    session.connect(s_get("read_holding_registers"))
    session.connect(s_get("ReadDiscreteInputs"))
    session.connect(s_get("ReadHoldingRegisters"))
    session.connect(s_get("ReadInputRegisters"))
    session.connect(s_get("WriteSingleCoil"))
    session.connect(s_get("WriteSingleRegister"))
    session.connect(s_get("ReadExceptionStatus"))
    session.connect(s_get("ReadExceptionStatusError"))
    session.connect(s_get("WriteMultipleCoils"))
    session.connect(s_get("ReportSlaveId"))
    session.connect(s_get("ReadFileSub"))
    session.connect(s_get("ReadFileRecord"))
    session.connect(s_get("WriteFileSub"))
    session.connect(s_get("WriteFileRecord"))
    session.connect(s_get("MaskWriteRegister"))
    session.connect(s_get("ReadWriteMultipleRegisters"))

    session.fuzz()


if __name__ == "__main__":
    target_ip = "10.38.4.15"
    start_cmds = []
    proc_name = ""
    pport = 502
    dport=26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
