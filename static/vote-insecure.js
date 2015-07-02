window.onload = function(){var tea = document.getElementById("tea");
			   tea.addEventListener("click", function(){
			       vote("tea");
			   });
			   
			   var coffee = document.getElementById("coffee");
			   coffee.addEventListener("click", function(){
			       vote("coffee");
			   });
			   console.log("Loaded!");
}

function vote(x) {
    var req=new XMLHttpRequest();
    req.open("POST", "vote/");
    req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    req.send("vote="+encodeURIComponent(x));
}
