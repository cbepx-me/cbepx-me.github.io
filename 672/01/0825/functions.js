function payload_finished(payload)
{
	setCookie("JB","DONE",1);
	setTimeout(function(){document.getElementById("progress").innerHTML="加载顺利完成!!";}, 3000);
	if(payload == "binloader"){
		setTimeout(function(){document.getElementById("progress").innerHTML="等待接收 Payload!! 请通过 9021 端口发送"; }, 7000);
	} else{
		setTimeout(function(){document.getElementById("progress").innerHTML="PS4 越狱 6.72 Payload 加载顺利完成 ✔"; }, 7000);
	}
}

function triggerFunction(payload){
	preloader();
	if(payload == "app2usb"){
		app2usb();
	}else if(payload == "backup"){
		backup();
	}else if(payload == "disableupdates"){
		disableupdates();
	}else if(payload == "dumper"){
		dumper();
	}else if(payload == "enablebrowser"){
		enablebrowser();
	}else if(payload == "enableupdates"){
		enableupdates();
	}else if(payload == "fanthreshold"){
		fanthreshold();
	}else if(payload == "ftp"){
		ftp();
	}else if(payload == "hen"){
		hen();
	}else if(payload == "historyblocker"){
		historyblocker();
	}else if(payload == "kernelclock"){
		kernelclock();
	}else if(payload == "kerneldumper"){
		kerneldumper();
	}else if(payload == "linuxloader"){
		linuxloader();
	}else if(payload == "mirahen"){
		mirahen();
	}else if(payload == "miranohb"){
		miranohb();
	}else if(payload == "miraunofficial"){
		miraunofficial();
	}else if(payload == "ps4debug"){
		ps4debug();
	}else if(payload == "restore"){
		restore();
	}else if(payload == "rifrenamer"){
		rifrenamer();
	}else if(payload == "todex"){
		todex();
	}else if(payload == "webrte"){
		webrte();
	}
	loader();
	payload_finished(payload);
}

function load_JB()
{	var jbDone=getCookie("JB");
	var spoofed=navigator.userAgent.indexOf("6.72")>=0 ? false : true;
	if (!spoofed && (jbDone == "" || jbDone == "START")){
		setCookie("JB","START",1);
		exploit();	
	}else{
		setTimeout(function(){document.getElementById("progress").innerHTML="PS4 越狱 6.72 功能顺利完成 ✔"; }, 500);
	}
}

function exploit(){
	document.getElementById("progress").innerHTML="正在运行破解功能!!";
	setTimeout(function(){jb();}, 500);
}

function load_payload(payload)
{	
	document.getElementById("progress").innerHTML="正在加载漏洞! 请等待!!";
	setCookie("JB","START",1);
	setTimeout(function(){triggerFunction(payload)}, 500);
}

function getCookie(name) {
  var name = name + "=";
  var decodedCookie = decodeURIComponent(document.cookie);
  var ca = decodedCookie.split(';');
  for(var i = 0; i < ca.length; i++) {
    var c = ca[i];
    while (c.charAt(0) == ' ') {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return "";
}

function setCookie(name, value, mins) {
  var d = new Date();
  d.setTime(d.getTime() + (mins*60*1000));
  var expires = "expires="+ d.toUTCString();
  document.cookie = name + "=" + value + ";" + expires + ";path=/";
}

function deleteCookie(name) {
  document.cookie = name + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
}
