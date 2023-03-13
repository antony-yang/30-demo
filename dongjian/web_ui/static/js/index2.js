var table,layer;
layui.use(['table','laypage','layer'], function(){
  table = layui.table;
  var laypage = layui.laypage;
  layer = layui.layer;
  var tasktable=table.render({
    elem: '#task'
    // ,page: true //开启分页
	,data:[]
    ,cols: [[ //表头
	  {type:'checkbox'}
      ,{field: 'task_name', title: '任务名称'}
      ,{field: 'save_time', title: '时间',width:"25%"}
      ,{field: 'hanle', title: '任务操作项',toolbar:'#barDemo',width:"25%"}
    ]]
  });
  table.on('tool(task)', function(obj){ //注：tool 是工具条事件名，task 是 table 原始容器的属性 lay-filter="对应的值"
    var data = obj.data; //获得当前行数据
    var layEvent = obj.event; //获得 lay-event 对应的值（也可以是表头的 event 参数对应的值）
    var tr = obj.tr; //获得当前行 tr 的 DOM 对象（如果有的话）
	var taskname=data.task_name;
	sessionStorage.setItem("symbol",JSON.stringify(data.symbol))
    if(layEvent === 'show'){ //查看
      layer.open({
		  type: 2,
		  title: '结果查看',
		  shadeClose: true,
		  shade: false,
		  area: ['800px', '600px'],
		  content: 'showResult.html?taskname='+taskname,
		  btn: ['关闭'],
		  yes: function(index, layero){
			  layer.close(index)
		  }
       });
    } 
  });
  
  $.ajax({//任务总数
  	url:PATH+'api/get_netzob_list_total_page',
  	type:'GET',
  	success:function(res){
  		if (res.res==1){
			var page=res.value
  			$.ajax({
  				url:PATH+'api/get_netzob_list_by_page/1',
  				type:'GET',
  				success:function(res){
  					if (res.res==1){
						var data=res.value;
						for (var i=0;i<data.length;i++){
							data[i].save_time=data[i].file_info_list[0].save_time
						}
  						table.reload('task', {
  						  data:data //设定异步数据接口的额外参数
  						});
  						//执行一个laypage实例
  						laypage.render({
  						  elem: 'page' //注意，这里的 test1 是 ID，不用加 # 号
  						  ,count:  page*11 //数据总数，从服务端得到
  						  ,limit:11//pagesize
						  ,prev:'<i class="layui-icon">&#xe603;</i>'
						  ,next:'<i class="layui-icon">&#xe602;</i>'
						  ,layout:['prev', 'page', 'next']
  						  ,jump: function(obj, first){
  						      //首次不执行
  						      if(!first){
  								  jumpTable(obj.curr)
  						      }
  						    }
  						});
  					}
  				},
  				error:function(res){
  					layer.msg("接口请求出错")
  				}
  			})
  		}else{
  			layer.msg(res.retmsg)
  		}
  	},
  	error:function(res){
  		layer.msg("接口请求出错")
  	}
  })
 
})

var currentPage=1;
function jumpTable(currPage){//
	$.ajax({
		url:PATH+'api/get_netzob_list_by_page/'+currPage,
		type:'GET',
		success:function(res){
			if (res.res==1){
				currentPage=currPage
				var data=res.value;
				for (var i=0;i<data.length;i++){
					data[i].save_time=data[i].file_info_list[0].save_time
				}
				table.reload('task', {
				  data: data //设定异步数据接口的额外参数
				});
			}
		},
		error:function(res){
			layer.msg("接口请求出错")
		}
	})
	
}

$("#return-back").click(function(){
    window.location.href = "/tableWeb"
})

$("#add-task").click(function(){
	layer.open({
	      type: 2,
	      title: '新建协议模糊测试',
	      shadeClose: true,
	      shade: false,
	      area: ['800px', '400px'],
	      content: 'addTaskModel.html',
		  btn: ['提交', '取消'],
		  yes: function(index, layero){
			  var body = layer.getChildFrame('body', index);
			  var formData=new FormData()
			  for(i=0;i<body.find("input[type=file]").length;i++){  
				var file=body.find("input[type=file]")[i].files[0];
			    formData.append("file", file);
			  } 
			  
			  var bpfFilter=body.find("#bpfFilter").val();
			  var importLayer=body.find("#importLayer").val();
			  if (!bpfFilter || !importLayer || !body.find("input[type=file]")[0].value){
				layer.msg("必填项不能为空");
				return;
			  }
			  formData.append("bpfFilter",bpfFilter);
			  formData.append("importLayer",importLayer);
			  
			 submitTask(formData);
			  layer.close(index)
		  },btn2: function(index, layero){
		  }
	    });
})

function submitTask(formData){
	$.ajax({
		url:PATH+'api/netzob',
		type:'POST',
		data:formData,
		cache: false,
		processData: false,
		contentType: false,
		success:function(res){
			if (res.res==1){
				 layer.msg(res.desc)
				
				$.ajax({//任务总数
					url:PATH+'api/get_netzob_list_total_page',
					type:'GET',
					success:function(res){
						if (res.res==1){
							var page=res.value
							laypage.render({
							  elem: 'page' //注意，这里的 test1 是 ID，不用加 # 号
							  ,count:  page*11 //数据总数，从服务端得到
							  ,limit:11//pagesize
							  ,prev:'<i class="layui-icon">&#xe603;</i>'
							  ,next:'<i class="layui-icon">&#xe602;</i>'
							  ,layout:['prev', 'page', 'next']
							  ,jump: function(obj, first){
							      //首次不执行
							      if(!first){
									  jumpTable(obj.curr)
							      }
							    }
							});
							jumpTable(currentPage);
						}else{
							layer.msg(res.desc)
						}
					},
					error:function(res){
						layer.msg("接口请求出错")
					}
				})
				
			}else{
				 layer.msg(res.value)
			}
		},
		error:function(res){
			layer.msg("接口请求出错")
		}
	})
}



