window.onload = function(){var tea = document.getElementById("tea");
			   tea.addEventListener("click", function(){
			       vote("tea");
			   });
			   
			   var coffee = document.getElementById("coffee");
			   coffee.addEventListener("click", function(){
			       vote("coffee");
			   });
			   var button = document.getElementById("button");
			   button.addEventListener("click", showresults);
}

function vote(x) {
    var pubkey = "BFqcfyJcH+Bx7xA9YjSxYXyVR5FIQeIH+XbeIZot+jIMnYH8nX5aOY397xXUOZiwzYvWFELsMJeSMSIHkHyR5K0=";
    //Just send an ElGamal encrypted request right now
    if (x=="tea"){
	var teaballot = mozvote.vote(pubkey,1);
	var coffeeballot = mozvote.vote(pubkey,0);
    } else {
	var teaballot = mozvote.vote(pubkey,0);
	var coffeeballot = mozvote.vote(pubkey,1);
    }
    var req=new XMLHttpRequest();
    req.open("POST", "vote/");
    req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    req.send("tea="+encodeURIComponent(teaballot)+"&coffee="+encodeURIComponent(coffeeballot));
}

function showresults(x) {
    var req = new XMLHttpRequest();
    req.open("GET", "results/");
    req.onload = displaycallback;
    req.send()
}

function displaycallback(){
    var data = JSON.parse(this.responseText);
    var teaplace = document.getElementById("teaplace");
    teaplace.innerHTML=data.tea;
    var coffeeplace = document.getElementById("coffeeplace");
    coffeeplace.innerHTML=data.coffee;
}

