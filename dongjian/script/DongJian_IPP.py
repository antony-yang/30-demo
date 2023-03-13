
from DongJian import *

param = {
	"param": {
		"dport": {
			"ness": 1,
			"default": 26002
		},
		"pport": {
			"ness": 1,
			"default": 2404
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
			"default": [
			]
		}
	},
	"proto": "ipp"
}

def fuzz(start_cmds, proc_name, target_ip, pport, dport, *args, **kwargs):

    sess = Session(
        target=Target(
            connection=SocketConnection(host=target_ip, port=pport, proto="tcp"),
        ),
        **kwargs
    )
    #ipp request
    s_initialize(name="Request")
    # header http header
    if s_block("Request-Header"):
        s_string("POST", name="Method", fuzzable=False)
        s_delim(" ", name='space-1',fuzzable=False)
        s_string("/ipp/print", name='Request-URI',fuzzable=False)
        s_delim(" ", name='space-2',fuzzable=False)
        s_string('HTTP/1.1', name='HTTP-Version_req',fuzzable=False)
        s_static("\r\n", name="Request-Line-CRLF_1")
        s_string("Connection: Keep-Alive", name="Connection_req",fuzzable=False)
        s_static("\r\n", name="Request-Line-CRLF_2")
        s_string("Content-Type: application/ipp", name="Content-Type_req",fuzzable=False)
        s_static("\r\n", name="Request-Line-CRLF_3")
        s_string("User-Agent: Windows Internet Print Protocol Provider", name="User-Agent_req",fuzzable=False)
        s_static("\r\n", name="Request-Line-CRLF_4")
        s_string("Content-Length", name="Content-Length_key_req",fuzzable=False)
        s_delim(":", name='colon',fuzzable=False)
        #s_dword(0x100, name="Content-Length_value_req")
        s_size(name="Content-Length_value_req", block_name="request_body", length=4, fuzzable=False,output_format="ascii")
        s_static("\r\n", name="Request-Line-CRLF_5")
        s_static("\r\n", name="Request-Line-CRLF_6")
        s_block_end("Request-Header")

     #body ipp
    if s_block("request_body"):
        s_word(0x02, name="version_number_req")
        s_word(0x0b, name="operation_id")


        #operation_id
        # define IPP_PRINT_JOB              0x0002 此标识开始打印数据
        # define IPP_PRINT_URI              0x0003
        # define IPP_VALIDATE_JOB         0x0004
        # define IPP_CREATE_JOB           0x0005
        # define IPP_SEND_DOC             0x0006
        # define IPP_SEND_URI              0x0007
        # define IPP_CANCEL_JOB           0x0008
        # define IPP_GET_JOB_ATTR         0x0009
        # define IPP_GET_JOBS              0x000A
        # define IPP_GET_PRINTER_ATTR    0x000B
        s_dword(0x123, name="request_id_req")

        #属性组 n bytes(0 or more)
        s_random("", min_length=0, max_length=0x10, name="attribute-group")
        s_byte(0x03, name="end_of_attributes_tag")
        s_block_end("request_body")




     # ipp response
    s_initialize(name="Response")
    if s_block("Response-header"):
        # header http header
        s_string('HTTP/1.1', name='HTTP-Version_resp')
        s_delim(" ", name='cut_1')
        s_string("200", name="http_status_code")
        s_delim(" ", name='cut_2')
        s_string("ok", name="[status_code_description")
        s_static("\r\n", name="Response-Line-CRLF_1")
        s_string("Content-Type: application/ipp", name="Content-Type_resp")
        s_static("\r\n", name="response-Line-CRLF_2")
        s_string("Content-Length", name="Content-Length_key_resp")
        s_delim(":", name='colon_resp_1')
        #s_dword(0x100, name="Content-Length_value_resp")
        s_size(name="Content-Length_value_resp", block_name="response_body", length=4, fuzzable=False)
        s_static("\r\n", name="response-Line-CRLF_3")
        s_static("\r\n", name="response-Line-CRLF_4")
        s_block_end("Response-header")



    #response_body
    if s_block("response_body"):
        s_word(0x02, name="version_number_resp")
        s_word(0x00, name="ipp_status_code")

        s_dword(0x123, name="request_id_resp")

        # 属性组 n bytes(0 or more)
        s_random("", min_length=0, max_length=0x10, name="operation_attributes_tag")
        s_random("", min_length=0, max_length=0x10, name="printer_attributes_tag")
        s_byte(0x03, name="end_of_attributes_tag")
        s_block_end("response_body")







    #sess.connect(s_get("Request"))
    sess.connect(s_get("Response"))
    sess.fuzz()


if __name__ == "__main__":
   # target_ip = "127.0.0.1"
    target_ip = "192.168.159.1"
    start_cmds = []
    proc_name = "ipp"
    pport = 80
    dport = 26002
    fuzz(start_cmds, proc_name, target_ip, pport, dport, script_start=True)
