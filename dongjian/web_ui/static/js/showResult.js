var table,layer;

layui.use(['table','laypage','layer'], function(){
  table = layui.table;
  var laypage = layui.laypage;
  layer = layui.layer;
 
  taskname=getQueryVariable("taskname")
  $.ajax({
  	url:PATH+'api/get_netzob_info',
  	type:'POST',
	data:{task_name:taskname},
  	success:function(res){
		if (res.res==1){
			var symbol=res.value.symbol;
			symbol=JSON.stringify(symbol,null,4);
			symbol = symbol.replace(/\\\\/g, "\\");
			symbol = symbol.replace(/\\n/g, "\\\n");
			$("#main pre").html(symbol)
			
		}else{
			layer.msg(res.value)
		}
  	},
  	error:function(res){
  		layer.msg("接口请求出错")
  	}
  })
})
function getQueryVariable(variable)//获取url参数
{
       var query = window.location.search.substring(1);
       query=query.split("=")
       return(decodeURI(query[1]));
}

