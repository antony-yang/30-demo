const PATH=''
layui.use(['element','table','laypage'], function(){
  //选项卡
  var element = layui.element;
  
  //table初始化
  var table = layui.table;
  table.render({
    elem: '#table1'//对应表格的id
    ,data:[]
    ,limit:11
    ,cols: [[
      {type:'checkbox'}
      ,{field:'id', title: 'ID', hide:true, width:0}
      ,{field:'run_id', title: 'RUNID', hide:true, width:0}
      ,{field:'taskname', title: '任务名称',width:'12%'}
      ,{field:'taskcreator', title: '创建者',width:'12%'}
      ,{field:'protocol', title: '协议类型',width:'8%'}
      ,{field:'ctime', title: '创建时间',width:'17%'}
      ,{field:'port', title: '端口',width:'8%'}
      ,{field:'targetip', title: '目标ip',width:'8%'}
      ,{field:'status', title: '状态',width:'6%'}
      ,{field:'handle', title: '操作',toolbar:'#table1Handle'}
    ]]
    ,id:"table1"//最好和表格id一致后续好操作
    ,done:function(data){
    	console.log(data)
    	for (let i=0;i<data.data.length;i++){
    	    if(data.data[i].status=="unfinished"){
    	        let $tr=$(".tableBox tbody tr").eq(i);
    	        $tr.find(".stopBtn").addClass("stop").prop("disabled",false);
    			$tr.find(".pauseBtn").addClass("pause2").prop("disabled",true);
    	    }
    		if (data.data[i].status=="finished"){
    			let $tr=$(".tableBox tbody tr").eq(i);
    			console.log($tr)
    			$tr.find(".stopBtn").addClass("stop2").prop("disabled",true);
    			$tr.find(".pauseBtn").addClass("pause2").prop("disabled",true);
    			
    		}
		    if (data.data[i].status=="unfinished" || data.data[i].status=="running" || data.data[i].status=="paused"){
			let $tr=$(".tableBox tbody tr").eq(i);
			$tr.find(".download").addClass("unfinished").prop("disabled",true);
                if(data.data[i].status=="paused"){
                    $tr.find(".pauseBtn").toggleClass("pause")
                }
		    }
    	}
    }
  });
  
  let tableparam={//任务列表参数
	page_id:1
  }
  loadTableData("table1",tableparam);
  
  //分页条
  //数据总条数
  var laypage = layui.laypage;
  let data={
  	module:0
  }
  getPageCount(laypage,"page1",data);
  
});

//用户名
function GetQueryString(name) { 
  var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)", "i"); 
  var r = window.location.search.substr(1).match(reg); //获取url中"?"符后的字符串并正则匹配
  var context = ""; 
  if (r != null) 
     context = r[2]; 
  reg = null; 
  r = null; 
  return context == null || context == "" || context == "undefined" ? "" : context; 
}
var account=GetQueryString("user")
if (account!=""){
     $(".account").text("用户："+account)
}

//加载表格数据
function loadTableData(id, data){//id指的是表格id
	$.ajax({  
		type: "GET",  
		//url: "/NSM/api/rest/fuzzyTest/getListByPage", 
		url:PATH+"/api/get_task_list_by_page/" + data["page_id"],
		dataType:"json",
		//data:data,
		success: function(result){ 
		//console.log(result)
			if(result.res!="1"){
				layer.msg(result.value);
			}else{		 	
				let data2=result.value;
				layui.use('table', function(){
				  //table初始化
				    var table = layui.table;
			        table.reload(id, {//这里的id是id:"table1"
			            elem: '#'+id
			            ,data: data2
			        });
				     
				});
			}	
		}, 
		error:function(e){  
			 layer.msg("后台接口报错！");
		}  
	});
}
function getPageCount(laypage,id,data){
	$.ajax({  
		type: "GET",  
		//url: "/NSM/api/rest/fuzzyTest/getListByPage", 
		url:PATH+"/api/get_task_list_total_page",//请求数据总数
		dataType:"json",
		//data:data,
		success: function(result){ 
			if(result.res!="1"){
				layer.msg(result.value);
				
			}else{		 	
				let count=result.value;
				//console.log(count)
				//执行一个laypage实例
			    laypage.render({
			    	 elem: 'page1',            //注意，这里的 page1 是 id，不用加 # 号
				 count: count * 11         //数据总数，从服务端得到
			    	,limit: 11
			    	,prev: '<em><</em>'
			    	,next: '<em>></em>'
			    	,jump: function(obj, first){//跳转页数
					    //obj包含了当前分页的所有参数，比如：
					    //console.log(obj.curr); //得到当前页，以便向服务端请求对应页的数据。
					    //首次不执行
					    if(!first){
					      let tableparam={//任务列表参数
							page_id:obj.curr
						  }
					      loadTableData("table1",tableparam)//请求任务列表
					    }
					  }
			    });
			}	
		}, 
		error:function(e){  
			 layer.msg("后台接口报错！");
		}  
	});
}

$(".container").on("click",".stopBtn",function(){
	let status=$(this).parents("tr").find("td[data-field=status]>div").text();
	console.log(status)
	let run_id=$(this).parent().parent().parent().find("td[data-field=run_id]>div").text();
	let data={run_id:run_id}//参数请根据需求来写
	if (status=="unfinished"){
		$(this).toggleClass("stop");
		doStart_Task(data)
	}
	else if (status=="running" || status=="paused"){
		doStop(data)
	}
	else{
		layer.msg("该任务已停止，无法停止")
	}
})

//点击暂停按钮
$(".container").on("click",".pauseBtn",function(){
	let status=$(this).parents("tr").find("td[data-field=status]>div").text();
	let run_id=$(this).parent().parent().parent().find("td[data-field=run_id]>div").text();
	let data={run_id}
	if (status=="running"){
        $(this).toggleClass("pause");
		doPause(data)
	}else if(status=="paused"){
		doStart(data)
	}else{
		layer.msg("该任务已完成、未开始或已暂停，无法暂停!")
	}
})
//点击查看
$(".container").on("click",".lookBtn",function(){
	let run_id=$(this).parent().parent().parent().find("td[data-field=run_id]>div").text();
	let data={run_id:run_id}
	//console.log(run_id)
	showFuzzingTestResult(data)
})


//点击删除
$(".container").on("click",".delBtn",function(){
	let run_id=$(this).parent().parent().parent().find("td[data-field=run_id]>div").text();
	let data={run_id:run_id}
	layer.confirm('确定删除该任务吗？', {
	  btn: ['是','否'] //按钮
	}, function(){
		 $.ajax({
			type: "POST",  
			url: PATH+"/api/delete_task",  
			//dataType:"json",
			contentType:"application/json; charset=utf-8",
			data:JSON.stringify(data),	
			success: function(result){ 
				if (result.res!=1){
					layer.msg(result.value)
					
				}else if(result.res=="1"){
					layer.msg("任务删除")
					let curr=$("#page1 .layui-laypage-curr").text();
					let tableparam={//任务列表参数
						page_id:Number(curr)
					  }
					loadTableData("table1",tableparam)
				}
			},
			error:function(e){  
				 layer.msg("后台接口报错！");
			}  
		 });
	}, function(){
	});
})

//点击任务回显
$(".container").on("click",".showTask",function(){
	let run_id=$(this).parent().parent().parent().find("td[data-field=run_id]>div").text();
	let data={run_id:run_id}
	$.ajax({
		type: "POST",  
		url: PATH+"/api/get_task_parameter",  
		//dataType:"json",
		contentType:"application/json; charset=utf-8",
		data:JSON.stringify(data),	
		success: function(result){ 
			if(result.res!="1"){
				layer.msg(result.value)
			}else{		 		
				let data2=result.value
				var showcon = JSON.stringify(data2, null, 4);
				showcon = showcon.replace(/\\\\/g, "\\");
				let html="<div class='popupBox'>"
						        +"<div class='popup'><pre>"+showcon+"</pre></div>"
						    +"</div>"
				html+="<div id='page2' class='page'></div>"
				layui.use('laypage', function(){
					layer.open({
					    type: 1,
					    title: '任务参数回显',
					    maxmin: true, //开启最大化最小化按钮
				            area: ['893px', '600px'],
					    content: html,
					});
				});
			}
		},
		error:function(e){  
			 layer.msg("后台接口报错！");
		}  
	});
})

//点击crash
$(".container").on("click",".crash",function(){
	let run_id=$(this).parent().parent().parent().find("td[data-field=run_id]>div").text();
	let data={run_id:run_id}
	new Promise((resolve,reject)=>{
		$.ajax({
			type:'POST',
			url:PATH+'/api/get_task_crash_total_page',
			data:JSON.stringify({run_id:run_id}),
			contentType:"application/json; charset=utf-8",
			success:function(result){
				if (result.res!=1){
					layer.msg(result.value)
				}else{
					resolve(result.value)
				}
			},
			error:function(){
				reject("后台接口报错！")
			}
		})
	}).then(count=>{
		$.ajax({
			type: "POST",  
			url: PATH+"/api/get_task_crash_by_page/1",  
			contentType:"application/json; charset=utf-8",
			data:JSON.stringify({run_id:run_id}),
			success: function(result){ 
				if(result.res!="1"){
					layer.msg(result.value)
				}else{		 		
					let data2=result.value
					var showcon = JSON.stringify(data2, null, 4);
					showcon = showcon.replace(/\\\\/g, "\\");
					let html="<div class='popupBox'>"
							        +"<div class='popup'><pre>"+showcon+"</pre></div>"
							    +"</div>"
					html+="<div id='page2' class='page'></div>"
					layui.use('laypage', function(){
						var laypage = layui.laypage;
						layer.open({
						    type: 1,
						    title: 'crash',
						    maxmin: true, //开启最大化最小化按钮
					            area: ['893px', '600px'],
						    content: html,
						    success:function(layero,index){
							  // 		分页条
							  // 		数据总条数
									// 参数设置
							let data={
								run_id:run_id
							}
							getCrashPage(laypage,"page2",count,data)
						  }
						});
					});
				}
			},
			error:function(e){  
				 layer.msg("后台接口报错！");
			}  
		});
	}).catch(err=>{
		
	})
	
})

function doStop(data){
	$.ajax({  
		type: "POST",  
		url: PATH+"/api/kill_task_by_name",  
		//dataType:"json",
		contentType:"application/json; charset=utf-8",
		data:JSON.stringify(data),	
		success: function(result){ 
			if(result.res!="1"){
				layer.msg("停止失败")
			}else{		 		
				layer.msg("停止成功");
				let curr=$("#page1 .layui-laypage-curr").text();
				let tableparam={//任务列表参数
					page_id:Number(curr)
				  }
				loadTableData("table1",tableparam)
			}
		},
		error:function(e){  
			 layer.msg("后台接口报错！");
		}  
	});
}

function doPause(data){
	$.ajax({  
		type: "POST",  
		url: PATH+"/api/suspend_task_by_name",
		contentType:"application/json; charset=utf-8",		
		data:JSON.stringify(data),
		success: function(result){ 
			if(result.res!="1"){
				layer.msg("暂停失败");
			}else{
				layer.msg("暂停成功");
				let curr=$("#page1 .layui-laypage-curr").text();
				let tableparam={//任务列表参数
					page_id:Number(curr)
				  }
				loadTableData("table1", tableparam)
			}
		},
		error:function(e){  
			 layer.msg("后台接口报错！");
		}  
	});
}

function doStart_Task(data){
	$.ajax({
		type: "POST",
		url: PATH+"/api/start_task",
		contentType:"application/json; charset=utf-8",
		data:JSON.stringify(data),
		success: function(result){
			if(result.res!="1"){
				layer.msg("启动失败")
			}else{
				layer.msg("启动成功");
				let curr=$("#page1 .layui-laypage-curr").text();
				let tableparam={//任务列表参数
					page_id:Number(curr)
				  }
				loadTableData("table1",tableparam)
			}
		},
		error:function(e){
			 layer.msg("后台接口报错！");
		}
	});
}

function doStart(data){
	$.ajax({  
		type: "POST",  
		url: PATH+"/api/resume_task_by_name",
		contentType:"application/json; charset=utf-8",		
		data:JSON.stringify(data),	
		success: function(result){ 
			if(result.res!="1"){
				layer.msg("启动失败")
			}else{		 		
				layer.msg("启动成功");
				let curr=$("#page1 .layui-laypage-curr").text();
				let tableparam={//任务列表参数
					page_id:Number(curr)
				  }
				loadTableData("table1",tableparam)
			}
		},
		error:function(e){  
			 layer.msg("后台接口报错！");
		}  
	});
}
//查看
function showFuzzingTestResult(data_in){
	$.ajax({  
			type: "POST",
			url:PATH+"/api/get_task_result_by_page/1",
			contentType:"application/json; charset=utf-8",
			data:JSON.stringify(data_in),
			success: function(result){ 
				if(result.res!=1){
					layer.msg("查看失败!");
				}else{	
					
					let data2=result.value
					var showcon = JSON.stringify(data2, null, 4);
					showcon = showcon.replace(/\\\\/g, "\\");
					let html="<div class='popupBox'>"
							        +"<div class='popup'><pre>"+showcon+"</pre></div>"
							    +"</div>"
					html+="<div id='page2' class='page'></div>"
					layui.use('laypage', function(){
						var laypage = layui.laypage;
						layer.open({
						    type: 1,
						    title: '结果查看',
						    maxmin: true, //开启最大化最小化按钮
					            area: ['893px', '600px'],
						    content: html,
						    success:function(layero,index){
							  		//分页条
							  		//数据总条数
									//参数设置
							let data={
								module:0
							}
							getResultPage(laypage,"page2",data_in)
						  }
						});
					});
				}	
				
			}, 
			error:function(e){  
				 layer.msg("后台接口报错！");
			}  
		});
}

//查看方法//点击弹窗里的分页时候
function reloadFuzzingTestResult(data){
	$.ajax({  
			type: "POST",  
//			url: "/NSM/api/rest/fuzzyTest/getTaskResult",  
			url:PATH+"/api/get_task_result_by_page/" + data["page_id"],
			//dataType:"json",
			contentType:"application/json; charset=utf-8",
			data:JSON.stringify(data["data_in"]),
			success: function(result){ 
				if(result.res!=1){
					layer.msg("查看失败!");
				}else{	
//					let data2=JSON.parse(result.data).value
					let data2=result.value
					var showcon = JSON.stringify(data2, null, 4);
					showcon = showcon.replace(/\\\\/g, "\\");
					$(".popupBox pre").html(showcon)
				}	
				
			}, 
			error:function(e){  
				 layer.msg("后台接口报错！");
			}  
		});
}


//结果里面的分页方法
function getResultPage(laypage,id,data){
	$.ajax({  
		type: "POST",  
		//url: "/NSM/api/rest/fuzzyTest/getListByPage", 
		url:PATH+"/api/get_task_result_total_page",//请求数据总数
		//dataType:"json",
		contentType:"application/json; charset=utf-8",
		data:JSON.stringify(data),
		success: function(result){ 
			if(result.res!="1"){
				layer.msg(result.value);
				
			}else{		 	
				//看文档好像获取到的是总页数，所以要模拟一个总数，不然分页条无法分页=》count=page*limit
				//如果返回的是count，直接获取到count就行
			//	let count=result.count;
				let page=result.value;
				let count=page*11//这个11是和下面limit对应的
				  //执行一个laypage实例
			    laypage.render({
			    	 elem: id 
			   	,count: count 
			    	,limit: 11
			    	,prev: '<em><</em>'
			    	,next: '<em>></em>'
			    	,jump: function(obj, first){//跳转页数
					    //obj包含了当前分页的所有参数，比如：
					    //console.log(obj.curr); //得到当前页，以便向服务端请求对应页的数据。
					    //首次不执行
					    if(!first){
					      let param={//结果列表参数
						     	page_id:obj.curr,
							data_in:data
						    }
					      reloadFuzzingTestResult(param)//请求结果列表
					    }
					  }
			    });
			}	
		}, 
		error:function(e){  
			 layer.msg("后台接口报错！");
		}  
	});
}

function getCrashPage(laypage,id,total,data_in){
	//看文档好像获取到的是总页数，所以要模拟一个总数，不然分页条无法分页=》count=page*limit
	//如果返回的是count，直接获取到count就行
	let page=total;
	let count=page*11//这个11是和下面limit对应的
	  //执行一个laypage实例
	laypage.render({
		 elem: id 
	,count: count 
		,limit: 11
		,prev: '<em><</em>'
		,next: '<em>></em>'
		,jump: function(obj, first){//跳转页数
			//obj包含了当前分页的所有参数，比如：
			//console.log(obj.curr); //得到当前页，以便向服务端请求对应页的数据。
			//首次不执行
			if(!first){
			  let param={//结果列表参数
					page_id:obj.curr,
					data_in:data_in
				}
			  reloadCrashResult(param)//请求结果列表
			}
		  }
	});
}
//查看方法//点击弹窗里的分页时候
function reloadCrashResult(data){
	$.ajax({  
		type: "POST",  
//			url: "/NSM/api/rest/fuzzyTest/getTaskResult",  
		url:PATH+"/api/get_task_crash_by_page/" + data["page_id"],
		//dataType:"json",
		contentType:"application/json; charset=utf-8",
		data:JSON.stringify(data["data_in"]),
		success: function(result){ 
			if(result.res!=1){
				layer.msg("查看失败!");
			}else{	
//					let data2=JSON.parse(result.data).value
				let data2=result.value
				var showcon = JSON.stringify(data2, null, 4);
				showcon = showcon.replace(/\\\\/g, "\\");
				$(".popupBox pre").html(showcon)
			}	
			
		}, 
		error:function(e){  
			 layer.msg("后台接口报错！");
		}  
	});
}

//点击日志下载按钮
$(".container").on("click",".download",function(){
	let status=$(this).parents("tr").find("td[data-field=status]>div").text();
	if (status!="unfinished"){
		let run_id=$(this).parent().parent().parent().find("td[data-field=run_id]>div").text();
		layui.use('layer', function(){
		    var layer = layui.layer;
		  	var index = layer.load(2, {
			  shade: [0.1,'#fff'], //0.1透明度的白色背景
			  content:'文件下载中',
			  skin:'layer-loading-class'
			});
			window.location.href=PATH+"/api/download2?run_id="+run_id;//下载地址
			layer.close(index)
		});
	}else{
		layer.msg("该任务已完成，无法暂停")
	}	
	
})

$(".jumpStartWeb").click(function(){
	if (account!=""){
	    window.location.href = "/index?user="+account;
	}else{
	    window.location.href = "/index"	
	}
})

$(".jumpProtoWeb").click(function(){
	    window.location.href = "/index2"
})
