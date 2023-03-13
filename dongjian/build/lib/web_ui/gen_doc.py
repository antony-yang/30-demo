#########################################
# bxj added

# sql = "select resultdb from info where taskname='%s'" % (self._taskname)
# c = self._db_cursor.execute(sql)
# rows = self._db_cursor._cursor._rows
# resdb = rows[0][0]
#
# # mongodb
# self._m_db = self._db_handler.getMC()["dongjian"]
# self._m_db_collection_cases = None
# self._m_db_collection_steps = None
# self._m_db_collection_crash_bin = None
# self._m_db_collection_parameter = None
#
# self._m_db_collection_parameter = self._m_db[self._taskname + "-parameter"]
# parameter_find = self._m_db_collection_parameter.find({}, {"_id": 0})
# parameter = list(parameter_find)[0]
#
# self._m_db_collection_crash_bin = self._m_db[resdb + "-crash_bin"]
# crash_info_find = self._m_db_collection_crash_bin.find({})
# crash_info = list(crash_info_find)
# if crash_info:
#     crash_info = crash_info[0]
#
# task_name = self._taskname
#
# start_time = '202' + self._taskname.split('202')[-1]
# pport = parameter['pport']
# proc_name = parameter['proc_name']
# protocol = parameter['protocol']
# target_ip = parameter['target_ip']
# taskcreator = parameter['taskcreator']
# tasktype = parameter['tasktype']
# start_cmds = parameter['start_cmds']
#
# total_cases = ''
# tested_cases = ''
# end_time = ''
# time_consuming = ''
# task_status = ''
#
# document = Document()
# document.add_heading(u'任务' + self._taskname + u'报告', 0)
# document.add_heading(u'一、任务摘要', level=1)
#
# document.add_paragraph(
#     u'任务名称：' + self._taskname, style='ListNumber'
# )
#
# document.add_paragraph(
#     u'任务创建时间:' + start_time, style='ListNumber'
# )
#
# document.add_paragraph(
#     u'fuzz协议：' + protocol, style='ListNumber'
# )
#
# document.add_paragraph(
#     u'协议名称：' + proc_name, style='ListNumber'
# )
#
# document.add_paragraph(
#     u'主机ip：' + target_ip, style='ListNumber'
# )
#
# document.add_paragraph(
#     u'端口号：' + str(pport), style='ListNumber'
# )
#
# document.add_paragraph(
#     u'fuzz参数：' + ''.join(start_cmds), style='ListNumber'
# )
#
# document.add_heading(u'二、任务信息', level=1)
#
# document.add_paragraph(
#     u'总测试用例数量:' + total_cases, style='ListNumber'
# )
# document.add_paragraph(
#     u'已测测试用例数量:' + tested_cases, style='ListNumber'
# )
# document.add_paragraph(
#     u'开始时间：' + start_time, style='ListNumber'
# )
# document.add_paragraph(
#     u'结束时间：' + end_time, style='ListNumber'
# )
# document.add_paragraph(
#     u'总耗时：' + time_consuming, style='ListNumber'
# )
# document.add_paragraph(
#     u'任务状态信息：' + task_status, style='ListNumber'
# )
#
# document.add_heading(u'三、崩溃点信息', level=1)
# document.add_paragraph(
#     str(crash_info), style='ListNumber'
# )
#
# document.add_page_break()
# document.save('../doc/' + self._taskname + ".doc")
#
# # pdf
# base_path = os.getcwd().rsplit("/", 1)[0]
# cmd = 'libreoffice --headless --convert-to pdf ' + base_path + '/doc/' + self._taskname + ".doc --outdir " + base_path + "/pdf/"
# p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
# p.wait(timeout=30)
# stdout, stderr = p.communicate()
# # if stderr:
# #     raise subprocess.SubprocessError(stderr)
#
# # xml
# doc = xml.dom.minidom.Document()
#
# root = doc.createElement('report')
# # 给根节点添加属性
# root.setAttribute('report', u'任务' + self._taskname + u'报告')
# # 将根节点添加到文档对象中
# doc.appendChild(root)
# summary = doc.createElement('summary')
#
# taskname_x = doc.createElement('taskname')
# taskname_x.appendChild(doc.createTextNode(self._taskname))
#
# creat_time_x = doc.createElement('creat_time')
# creat_time_x.appendChild(doc.createTextNode(start_time))
#
# fuzzing_agree = doc.createElement('protocol')
# fuzzing_agree.appendChild(doc.createTextNode(protocol))
#
# host_ip = doc.createElement('host_ip')
# host_ip.appendChild(doc.createTextNode(target_ip))
#
# port_x = doc.createElement('port')
# port_x.appendChild(doc.createTextNode(str(pport)))
#
# fuzzing_param = doc.createElement('fuzzing_param')
# fuzzing_param.appendChild(doc.createTextNode(''.join(start_cmds)))
#
# summary.appendChild(taskname_x)
# summary.appendChild(creat_time_x)
# summary.appendChild(fuzzing_agree)
# summary.appendChild(host_ip)
# summary.appendChild(port_x)
# summary.appendChild(fuzzing_param)
#
# task_info = doc.createElement('task_info')
#
# total_cases_x = doc.createElement('total_cases')
# total_cases_x.appendChild(doc.createTextNode(total_cases))
#
# tasted_cases_x = doc.createElement('tested_cases')
# tasted_cases_x.appendChild(doc.createTextNode(tested_cases))
#
# start_time_x = doc.createElement('start_time')
# start_time_x.appendChild(doc.createTextNode(start_time))
#
# end_time_x = doc.createElement('end_time')
# end_time_x.appendChild(doc.createTextNode(str(end_time)))
#
# time_consuming_x = doc.createElement(' time_consuming')
# time_consuming_x.appendChild(doc.createTextNode(str(time_consuming)))
#
# task_status_x = doc.createElement('task_status')
# task_status_x.appendChild(doc.createTextNode(str(task_status)))
#
# task_info.appendChild(total_cases_x)
# task_info.appendChild(tasted_cases_x)
# task_info.appendChild(start_time_x)
# task_info.appendChild(end_time_x)
# task_info.appendChild(time_consuming_x)
# task_info.appendChild(task_status_x)
#
# crash = doc.createElement('crash')
#
# crash_node = doc.createElement('crash_node')
# crash_node.appendChild(doc.createTextNode(str(crash_info)))
# crash.appendChild(crash_node)
#
# root.appendChild(summary)
# root.appendChild(task_info)
# root.appendChild(crash)
#
# fp = open(r'../xml/' + self._taskname + '.xml', 'w')
#
# doc.writexml(fp, indent='', addindent='\t', newl='\n', encoding='utf-8')
# fp.close()
#
# # excel
# report_excel = xlwt.Workbook(encoding='utf-8')
#
# summary_sheet = report_excel.add_sheet('一、任务摘要')
#
# summary_sheet.write(0, 0, '任务名称')
# summary_sheet.write(0, 1, self._taskname)
#
# summary_sheet.write(1, 0, u'任务创建时间')
# summary_sheet.write(1, 1, str(start_time))
#
# summary_sheet.write(2, 0, u'fuzz协议')
# summary_sheet.write(2, 1, protocol)
#
# summary_sheet.write(3, 0, u'协议名称')
# summary_sheet.write(3, 1, proc_name)
#
# summary_sheet.write(4, 0, u'主机ip')
# summary_sheet.write(4, 1, target_ip)
#
# summary_sheet.write(5, 0, u'端口号')
# summary_sheet.write(5, 1, pport)
#
# summary_sheet.write(6, 0, u'fuzz参数')
# summary_sheet.write(6, 1, start_cmds)
#
# info_sheet = report_excel.add_sheet(u'二、任务信息')
#
# info_sheet.write(0, 0, u'总测试用例数量')
# info_sheet.write(0, 1, str(total_cases))
#
# info_sheet.write(1, 0, u'已测测试用例数量')
# info_sheet.write(1, 1, str(tested_cases))
#
# info_sheet.write(2, 0, u'开始时间')
# info_sheet.write(2, 1, str(start_time))
#
# info_sheet.write(3, 0, u'结束时间')
# info_sheet.write(3, 1, str(end_time))
#
# info_sheet.write(4, 0, u'总耗时')
# info_sheet.write(4, 1, str(time_consuming))
#
# info_sheet.write(5, 0, u'任务状态信息')
# info_sheet.write(5, 1, str(task_status))
#
# crash_sheet = report_excel.add_sheet(u'三、崩溃点信息')
# crash_sheet.write(0, 0, str(crash_info))
#
# report_excel.save(r'../excel/' + self._taskname + '.xls')

#########################################