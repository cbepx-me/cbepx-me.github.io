function allset(info) {
      document.getElementById("loader").style.display = "none";
      document.getElementById("allset").style.display = "block";
      if(info!="") window.allset.innerHTML=info;
    }
function awaitpl() {
  document.getElementById("loader").style.display = "none";
  document.getElementById("awaiting").style.display = "block";
}

function fail(info) {
  document.getElementById("loader").style.display = "none";
  document.getElementById("fail").style.display = "block";
}
var load_hen = function (){
	if(testMira != '0') {
      var code_addr = new int64(0x26100000, 0x00000009);
      var buffer = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);
      // Load HEN-VTX
      if (buffer == '926100000') {
        writeHomebrewEN(p, code_addr.add32(0x100000));
      }
      // Launch HEN-VTX
      p.fcall(code_addr);
      // Zero
      for(var i = 0; i < 0x300000; i += 8)
      {
        p.write8(code_addr.add32(i), 0);
      }
      // Load Mira
      if (buffer == '926100000') {
        writeMira(p, code_addr.add32(0x100000));
      }
      // Launch Mira
      p.fcall(code_addr);
      // Test if payloads ran successfully, if not, refresh
      testMira = p.syscall("sys_setlogin", p.stringify("root"))

      if(testMira != '0')
      {
        location.reload();
      }
      // All done all done!
      allset("");
    }
}
var load_PL = function (name){
	
      var script=document.createElement('script');
        script.src=name+".js";
      
        document.getElementsByTagName('head')[0].appendChild(script);
     

      setTimeout(function(){
      var code_addr = new int64(0x26100000, 0x00000009);
      var buffer = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);
      // Load HEN-VTX
      if (buffer == '926100000') {
        loadPL(p, code_addr.add32(0x100000));
      }
      // Launch HEN-VTX
      p.fcall(code_addr);
      // Zero
      for(var i = 0; i < 0x300000; i += 8)
      {
        p.write8(code_addr.add32(i), 0);
      }
       },500);
      allset(name+" 已经成功加载;");
    }

var binload = function (){
      // Load payload launcher
      var code_addr = new int64(0x26100000, 0x00000009);
      var buffer = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);
      if (buffer == '926100000') {
        try {
          var createThread = window.webKitBase.add32(0x779390);
          var shellbuf = p.malloc32(0x1000);
          var shcode = [0x31fe8948, 0x3d8b48c0, 0x00003ff4, 0xed0d8b48, 0x4800003f, 0xaaf3f929, 0xe8f78948, 0x00000060, 0x48c3c031, 0x0003c0c7, 0x89490000, 0xc3050fca, 0x06c0c748, 0x49000000, 0x050fca89, 0xc0c748c3, 0x0000001e, 0x0fca8949, 0xc748c305, 0x000061c0, 0xca894900, 0x48c3050f, 0x0068c0c7, 0x89490000, 0xc3050fca, 0x6ac0c748, 0x49000000, 0x050fca89, 0x909090c3, 0x90909090, 0x90909090, 0x90909090, 0xb8555441, 0x00003c23, 0xbed23153, 0x00000001, 0x000002bf, 0xec834800, 0x2404c610, 0x2444c610, 0x44c70201, 0x00000424, 0x89660000, 0xc6022444, 0x00082444, 0x092444c6, 0x2444c600, 0x44c6000a, 0xc6000b24, 0x000c2444, 0x0d2444c6, 0xff78e800, 0x10baffff, 0x41000000, 0x8948c489, 0xe8c789e6, 0xffffff73, 0x00000abe, 0xe7894400, 0xffff73e8, 0x31d231ff, 0xe78944f6, 0xffff40e8, 0x48c589ff, 0x200000b8, 0x00000926, 0xc300c600, 0xebc38948, 0x801f0f0c, 0x00000000, 0x01489848, 0x1000bac3, 0x89480000, 0xe8ef89de, 0xfffffef7, 0xe87fc085, 0xe8e78944, 0xfffffef8, 0xf1e8ef89, 0x48fffffe, 0x200000b8, 0x00000926, 0x48d0ff00, 0x5b10c483, 0xc35c415d, 0xc3c3c3c3];
          for (var i = 0; i < shcode.length; i++) {
            shellbuf.backing[i] = shcode[i];
          }
          p.syscall("sys_mprotect", shellbuf, 0x4000, 7);
        } catch (e) { alert(e); }
      }
      // Launch loader
      p.fcall(createThread, shellbuf, 0, p.stringify("loader"));
      awaitpl();
    }

var runPayload = function(){
  if(window.exec_type==0)load_hen();
  else if(window.exec_type==1){binload();}
  else load_PL(window.exec_type);
}
