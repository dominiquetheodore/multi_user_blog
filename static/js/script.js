
$(document).ready(function(){
	var post_id = $("#post_id").val();
	$("#thumb").click(function(){
		$.post("/vote", {
			post_id: post_id
		}, function(data) {
			var output = $.parseJSON(data);
			if (output.message)
			{
				// add to the vote count 
				var votes = parseInt($("#votes").text(), 10) + 1				
				$("#votes").text(votes);
				if (output.unliked) {
					// update the unlike count if user had unliked the post previously
					var unlikes = parseInt($("#unlikes").text(), 10) - 1
					$("#unlike_label").hide();
					$("#unlikes").text(unlikes);
					$("#unlike_label_perm").hide();
				}

				alert(output.message);
				$("#like_label").show();
				$('#thumb').css("pointer-events", "none");
			}
			else
			{
				alert(output.error)
			}

		});
	});

	$("#thumb_down").click(function(){
		$.post("/unlike", {
			post_id: post_id
		}, function(data) {
			var output = $.parseJSON(data);
			if (output.message)
			{
				var unlikes = parseInt($("#unlikes").text(), 10) + 1
				$("#unlikes").text(unlikes);
				if (output.liked) {
					var likes = parseInt($("#votes").text(), 10) - 1
					$("#votes").text(likes);
					$("#like_label").hide();
					$("#like_label_perm").hide();
				}
				alert(output.message);
				$("#unlike_label").show();
				$('#thumb_down').css("pointer-events", "none");
			}
			else
			{
				alert(output.error);
			}

		});
	});

	$("#edit_btn").click(function(){
		user = $("#username").val();
		author = $("#author").val();

		if (!user)
		{
			alert("you must be signed in to edit and delete posts");
			location.replace("/login");
		}
		else
		{
			if (user == author)
			{
				$("#myModal").modal();
			}
			else
			{
				$("#errorModal").modal();
			}
		}
		

		
	});

	$("#edit_post").click(function(){
		var subject = $("#subject").val();
		var content = $("#content").val();
		var post_id = $("#post_id").val();
		$.post("/edit", {
			subject: subject,
			content: content,
			post_id: post_id
		}, function(data) {
			var output = $.parseJSON(data);
			if (output.error)
			{
				alert(output.error);
			}
			else
			{
				alert(output.message);
				location.replace("/blog/"+post_id)
			}

		});

	});

	$("#delete_post").click(function(){
		var post_id = $("#post_id").val();
		user = $("#username").val();
		author = $("#author").val();

		if (!user)
		{
			alert("you must be signed in to edit and delete posts");
			location.replace("/login");
		}
		else
		{
			if (user == author)
			{
				$.post("/delete", {
					post_id: post_id
				}, function(data) {
					var output = $.parseJSON(data);
					if (output.error)
					{
						alert(output.error);
					}
					else
					{
						alert(output.message);
						location.replace("/blog")
					}
				});
			}
			else
			{
				$("#errorModal").modal();
			}
		}
	});

	$("#delete_btn").click(function(){
		user = $("#username").val();
		author = $("#author").val();

		if (!user)
		{
			alert("you must be signed in to edit and delete posts");
			location.replace("/login");
		}
		else
		{
			if (user == author)
			{
				$("#deleteModal").modal();
			}
			else
			{
				$("#errorModal").modal();
			}
		}
	});

	$("#comment_btn").click(function(){
		user = $("#username").val();

		if (!user)
		{
			alert("you must be signed in to comment, edit and delete posts");
			location.replace("/login");
		}
		else
		{
			var post_id = $("#post_id").val();
			var user = $("#username").val();
			var comment = $("#comment").val();
			$.post("/comment", {
					post_id: post_id,
					user: user,
					comment: comment
				}, function(data) {
					var output = $.parseJSON(data);
					if (output.error)
					{
						alert(output.error);
					}
					else
					{
						alert(output.message);
						location.replace("/blog/"+post_id)
					}
			});
		}
	});

	$(".edit_comment_btn").click(function(){
		var div_id = $(this).parent().closest('.panel').attr('id');
		$.post("/commentbyid", {
					comment_id: div_id,
				}, function(data) {
					var output = $.parseJSON(data);
					if (output.error)
					{
						alert(output.error);
					}
					else
					{
						$("#comment_content").val(output.comment);
						$("#comment_to_edit").val(div_id);
						$("#commentModal").modal();
					}
			});
	});

	$("#edit_comment").click(function(){
		var post_id = $("#post_id").val();
		var comment = $("#comment_content").val();
		var comment_id = $("#comment_to_edit").val();
		$.post("/editcomment", {
					comment_id: comment_id,
					comment: comment
				}, function(data) {
					var output = $.parseJSON(data);
					if (output.error)
					{
						alert(output.error);
					}
					else
					{
						alert(output.message);
						location.replace("/blog/"+post_id)
					}
			});
	});

	$(".delete_comment_btn").click(function(){
		var div_id = $(this).parent().closest('.panel').attr('id');
		$("#deletecommentModal").modal();
		$("#delete_comment").click(function(){
			$.post("/delete_comment", {
					comment_id: div_id,
				}, function(data) {
					var output = $.parseJSON(data);
					if (output.error)
					{
						alert(output.error);
					}
					else
					{
						alert(output.message);
						$("#deletecommentModal").modal('hide');
						$("#"+div_id).remove();
					}
			});
		})
	});

});