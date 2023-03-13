$(".addfile").click(function(){
	var html='<div class="file-box" style="margin-left: 4px;">'
					+'<label>'
					+'</label>'
					+'<input class="file-input" placeholder="请选择文件"/>'
					+'<input class="file" type="file" name="file" accept=".pcap"/>'
					+'<div class="removefile">'
						+'<img src="static/img/del2.png"/>'
					+'</div>'
				+'</div>'
	$(".rule-box").before(html)
})
$("#form-box").on("click",".removefile",function(){
	$(this).parents(".file-box").remove()
})
$("#form-box").on("change","input[type=file]",function(){
	$(this).parents(".file-box").find(".file-input").val($(this).val());
})
