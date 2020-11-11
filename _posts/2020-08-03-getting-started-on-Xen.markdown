---
layout: post
title:  "HVMI demo setup on Xen"
date:   2020-08-10 11:52:00 +0300
author: Cristi Anichitei
---

In the [previous blog post](/blog/introspection/2020/07/30/introduction.html) we talked about what HVMI is and how it works, and now we will talk about how to get the example daemon working with Xen 4.11. We will be using Ubuntu 20.04 as a development environment.

For a KVM guide check [HVMI demo setup on KVM](/blog/2020/08/10/getting-started-on-kvm.html).

We will build and install the core introspection library (`libintrocore`), the [exceptions](https://github.com/hvmi/hvmi/tree/master/exceptions) and [guest support](https://github.com/hvmi/hvmi/tree/master/cami) files needed at runtime, and the example daemon (`hvmid`).

I'll be running HVMI inside a dedicated VM, but for Xen the results should be the same if HVMI is installed inside dom0.

At each step we will need various tools and libraries, so let's get that out of the way and install everything now:

```shell
sudo apt install -y git build-essential automake libtool libxen-dev cmake python3.8 python3-pip libboost-dev libjsoncpp-dev
pip install pyyaml
```

Note that the minimum required `cmake` version is `3.13`. If that is not available, you can get a newer version from [PyPI](https://pypi.org/project/cmake/):

```shell
pip install cmake
```

## Building and installing libintrocore

First, we need to get HVMI:

```shell
git clone --recurse-submodules https://github.com/hvmi/hvmi.git
```

Now we need to build `libintrocore`, and the exceptions and guest support files. All of these are handled by cmake:

```shell
cd hvmi
mkdir _build
cd _build
cmake ..  -DCMAKE_BUILD_TYPE=Release
make all
sudo make install
```

This should build and install everything we need.

If all we wanted to do was to develop an integration for the library, then this would have been enough, but we also want to start introspecting some VMs. For that, we need `hvmid`.

## Building and installing libbdvmi

To build `hvmid` we first need [libbdvmi](https://github.com/bitdefender/libbdvmi)

We'll just follow the [instructions](https://github.com/bitdefender/libbdvmi#usage) from the `libbdvmi` repository:

```shell
git clone https://github.com/bitdefender/libbdvmi
cd libbdvmi
./bootstrap
./configure
make
sudo make install
```

## Building and installing hvmid

Now, from the `daemon` directory:

```shell
mkdir _build
cd _build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
sudo make install
```

## Running hvmid

All that's left to do is to run `hvmid` and start a VM to be introspected:

```shell
./hvmid --start
```

To stop the daemon use:

```shell
./hvmid --kill
```

You can use `journalctl -t hvmid` to check the logs. You should see something like this (note that I will skip some uninteresting log lines):

```text
Aug 03 14:28:46 sva hvmid[3577]: Hypervisor Memory Introspection Daemon starting
Aug 03 14:28:46 sva hvmid[3577]: Loading default policy file /usr/local/etc/hvmid/policies/default.json
Aug 03 14:28:46 sva hvmid[3577]: Hardware concurrency: 2
Aug 03 14:28:46 sva hvmid[3577]: Registering handlers
Aug 03 14:28:46 sva hvmid[3577]: Waiting for domains to be started
Aug 03 14:28:46 sva hvmid[3577]: [b322436f-aea1-8c46-2187-fea0962be789] Found domain: 'Windows-7x64'
Aug 03 14:28:46 sva hvmid[3577]: Loading policy file /usr/local/etc/hvmid/policies/b322436f-aea1-8c46-2187-fea0962be789.json
Aug 03 14:28:47 sva hvmid[3601]: [b322436f-aea1-8c46-2187-fea0962be789] max_memkb: 4195328, maxGPFN: 0x100100
Aug 03 14:28:47 sva hvmid[3601]: [b322436f-aea1-8c46-2187-fea0962be789] Setting page cache limit to 512 mappings
Aug 03 14:28:47 sva hvmid[3601]: [b322436f-aea1-8c46-2187-fea0962be789] The hypervisor backend has chosen a page cache limit of 512 mappings
Aug 03 14:28:47 sva hvmid[3601]: [b322436f-aea1-8c46-2187-fea0962be789] VM_EVENT_INTERFACE_VERSION: 0x000000x3
Aug 03 14:28:47 sva hvmid[3601]: [b322436f-aea1-8c46-2187-fea0962be789] Running on Xen 4.11.1-7.5
Aug 03 14:28:47 sva hvmid[3601]: [b322436f-aea1-8c46-2187-fea0962be789] Guest start time: 2782542652
```

From the above log we can see that a new VM was found, named `Windows-7x64`, with the UUID `b322436f-aea1-8c46-2187-fea0962be789`. In the following examples I'll strip a few columns of the logs, to make them easier to read.

```text
introcore.c : 247 IntroCore initialised: version 1.132.1, build 00011, changeset 1fdd5a1, built on Jul 31 2020 08:02:03 from branch master
Introcore init complete
MaxGPFN: 0x10fbff
Introcore about to be initialized with options 0x3f7eb3ffffff: km_nt km_hal km_hal_heap_exec km_hal_int_ctrl km_ssdt km_idt km_hdt km_sys_cr3 km_token km_nt_drivers km_av_drivers km_xen_drivers km_drvobj km_cr4 km_msr_syscall km_idtr km_self_map_entry km_gdtr kvm_logger_ctx km_nt_eat_reads um_misc_procs um_sys_procs evt_process evt_module evt_os_crash evt_process_crash agent_injection full_path_protection bugcheck_cleanup in_guest_pt_filter
Loading live update file /usr/local/var/hvmid/intro_live_update.bin
introapi.c : 133 [INTRO-INIT] New guest notification, handle = 0x7f46bcca35a0
introapi.c : 135 [INTRO-INIT] Will use options: 0x00003f7eb3ffffff
update_guests.c : 1610 [INFO] Loaded cami version 1.4 build 0
guests.c : 643 [INTRO-INIT] Will try 0 time to static init the guest on CPU 01 with EFER 0x00000d01 and 4-level paging mode...
guests.c : 660 [INTRO-INIT] CPU 00: CR0 = 80050031, CR3 = 0000000000187000, CR4 = 000506f8, RIP = fffff88001a28ae2
guests.c : 660 [INTRO-INIT] CPU 01: CR0 = 80050031, CR3 = 0000000000187000, CR4 = 000506f8, RIP = fffff800028f479a
guests.c : 249 [INTRO-INIT] Found the syscall handler 3 address at 0xfffff80002a30bc0
guests.c : 337 [INTRO-INIT] Found the syscall/interrupt handler address at fffff80002a30bc0
guests.c : 675 [INTRO-INIT] Identified OS type Windows
guests.c : 683 [INTRO-INIT] Guest has KPTI installed: 1, enabled: 1
winguest.c : 2825 [INTRO-INIT] IA32_GS_BASE_MSR = 0xfffff88003040000
winguest.c : 2474 [INTRO-INIT] Active CPU Count: 2
winguest.c : 2865 [INTRO-INIT] Found SYSCALL handler @ 0xfffff80002a30bc0
winguest.c : 2580 [INFO] Found a possible offset instruction: MOV       rsp, qword ptr gs:[0x6000]
winguest.c : 2604 [INFO] Found a valid second instruction: MOV       cr3, rsp
winguest.c : 2605 [INFO] We will use the last possible offset instruction!
winguest.c : 2620 [INTRO-INIT] Found KernelDirectoryTableBase offset in PCR at 6000
winguest.c : 2629 [INTRO-INIT] Found PCR at 0xfffff88003040000
winguest.c : 2891 [INTRO-INIT] Found a valid cr3 at: 0x000000007f2a6000
winguest.c : 2903 [INTRO-INIT] Found first interrupt handler @ 0xfffff80002a2f800
winguest.c : 2308 [INFO] Found PsNtosImageBase = 0xfffff8000285e000 at address 0xfffff80002afb378!
winguest.c : 2920 [INTRO-INIT] Found the base of the ntoskrnl.exe [SYSCALL] @ VA 0xfffff8000285e000
winguest.c : 2308 [INFO] Found PsNtosImageBase = 0xfffff8000285e000 at address 0xfffff80002afb378!
winguest.c : 2938 [INTRO-INIT] Found the base of the ntoskrnl.exe [IDT]     @ VA 0xfffff8000285e000
winguest.c : 2091 [INFO] 3 supported os versions from cami
winguest.c : 2138 [WINGUEST STATIC] Found an NtBuildNumber 0xf0001db1 (7601) @ 0xfffff8000286814c
winguest.c : 2681 [INFO] KPCR [1] @ 0xfffff88003040000
winguest.c : 2694 [INFO] Idle thread [1] @ 0xfffff8800304f0c0
winguest.c : 2722 [INFO] Found a potentially valid idle process at offset 0x00000210 -> 0xfffff80002a52680
winguest.c : 2741 [INFO] Found a valid idle process cr3 at offset 0x00000028 @ 0xfffff80002a526a8 -> 0x0000000000187000
winguest.c : 2993 [INTRO-INIT] Found idle process CR3: 0x0000000000187000
winguest.c : 414 [SELFMAP] Found index = 493 (0x1ed)
winguest.c : 1972 [WINGUEST STATIC] All sections were present in memory!
winguest.c : 1269 [INTRO-INIT] Found API function PsCreateSystemThread @ 0xfffff80002b7eda4...
winguest.c : 1278 [INTRO-INIT] Found API function ExAllocatePoolWithTag @ 0xfffff80002a37010...
winguest.c : 1287 [INTRO-INIT] Found API function ExFreePoolWithTag @ 0xfffff80002a37cc0...
winguest.c : 1303 [INTRO-INIT] Found NtBuildNumber @ 0xfffff8000286814c with value 0xf0001db1...
winguest.c : 1320 [INTRO-INIT] Found NtBuildLab @ 0xfffff80002868150 with value: `7601.win7sp1_ldr_escrow.200102-1707`
winguest.c : 1494 [INFO] Identified OS type Windows, version 7601
winguest.c : 1495 [INFO] Guest has KPTI Installed
winguest.c : 247 [INTRO-INIT] Found PFN database: 0xfffffa8000000000
winguest.c : 225 [INTRO-INIT] Found process list head: 0xfffff80002a79940
winguest.c : 209 [INTRO-INIT] Found loaded module list: 0xfffff80002a97c90
winguest.c : 366 [INTRO-INIT] System CR3 is 0x0000000000187000!
winguest.c : 1522 [INTRO-INIT] Kernel objects successfully identified!
```

The version of the guest operating system was succesfully identified: it is a 64-bit Windows 7 SP1, build number 7601 with KPTI installed. We can also see that `libintrocore` idenfied some APIs exported by the kernel, as well as some interesting kernel objects.

```text
windriver.c : 443 [DRIVER] Driver 'ntoskrnl.exe' @ 0xfffffa8003350480 (base: 0xfffff8000285e000, hash: 0xe2d047ab) just loaded
windriver.c : 755 [DRIVER] Adding protection on driver 'ntoskrnl.exe' at fffff8000285e000...
windriver.c : 808 [DRIVER] ntoskrnl.exe @ 0xfffff8000285e000 has timedate stamp 0x5e0ead5e and size 0x005dd000
windriver.c : 857 [DRIVER] Skipping section INITKDBG...
windriver.c : 443 [DRIVER] Driver 'hal.dll' @ 0xfffffa8003350390 (base: 0xfffff80002816000, hash: 0xff76fb41) just loaded
windriver.c : 755 [DRIVER] Adding protection on driver 'hal.dll' at fffff80002816000...
windriver.c : 808 [DRIVER] hal.dll @ 0xfffff80002816000 has timedate stamp 0x5e0eb60c and size 0x00048000
winguest.c : 1559 [INTRO-INIT] Kernel loaded @ 0xfffff8000285e000 size of image = 0x5dd000 timedate stamp = 0x5e0ead5e
```

And finally, we see that protection for the core kernel module (`ntoskrnl.exe`) was activated.

Starting a protected process should generate logs similar to:

```text
winprocess.c : 712 [PROCESS] Process `chrome.exe` with PID 1664 and EPROCESS `0xfffffa800395b620` started with command line `"c:\program files (x86)\google\chrome\application\chrome.exe" `
winprocess.c : 1872 [WINPROC] Process `chrome.exe` has Exploit Guard Disabled
winprocesshp.c : 637 [INFO] Heap stats: total size: 2088869888 bytes, free: 1090080768 bytes
winprocess.c : 3148 [PROCESS] Protecting process chrome.exe with CR3 0x000000006fb88000, EPROC 0xfffffa800395b620, WOW64 0, PEB at 0x000007fffffdf000,PEB32 at 0x0000000000000000, Parent 0xfffffa8005d053e0, ProtMask: 0x400005fc, the process is being created.
winvad.c : 2792 [WINVAD] Starting static scan for process 0xfffffa800395b620 from root @ 0xfffffa800395ba68 = 0xfffffa800395ba6b
winvad.c : 1987 [WINVAD] -------> Special Win 7/8 case: 0xfffffa800395ba68 is not an actual VAD. Left = 0x0000000000000000 Right = 0xfffffa8003968160
winvad.c : 2745 [WINVAD] VAD 0xfffffa8004b219e0 found at static scan on level 3
winvad.c : 2745 [WINVAD] VAD 0xfffffa8003653160 found at static scan on level 4
winummodule.c : 1126 [MODULE] Module '\windows\system32\ntdll.dll' (be9d4ec5) just loaded at 0x0000000077180000 in process 'chrome.exe' (pid = 1664)
winumcache.c : 695 [WINUMCACHE] Create cache for module 'ntdll.dll', wow64: 0, dirty: 0.
swapmem.c : 538 [SWAPMEM] Page 77180000 is at 0 with flags 0 and opts 2, scheduling #PF injection to read 4096 bytes...
winvad.c : 2745 [WINVAD] VAD 0xfffffa8005dc6410 found at static scan on level 2
winvad.c : 2745 [WINVAD] VAD 0xfffffa8004d6b9e0 found at static scan on level 3
winvad.c : 2745 [WINVAD] VAD 0xfffffa8003968160 found at static scan on level 1
winummodule.c : 1126 [MODULE] Module '\program files (x86)\google\chrome\application\chrome.exe' (8eb0d21f) just loaded at 0x000000013ffc0000 in process 'chrome.exe' (pid = 1664)
winummodule.c : 320 [MODULE] Main module for process fffffa800395b620 (subsystem 1) has loaded!
winummodule.c : 325 [MODULE] Protecting module with base 0x000000013ffc0000 -> 0x000000006fb88000 against unpacking.
winummodule.c : 1579 [MODULE] Protecting pageable section: 0x000000013ffc1000, VA space 0x000000006fb88000, length 131855
winumdoubleagent.c : 715 [INFO] `\program files (x86)\google\chrome\application\chrome.exe` is NOT from native subsystem. Subsystem flag = 2
winvad.c : 2745 [WINVAD] VAD 0xfffffa8005984670 found at static scan on level 3
winummodule.c : 1126 [MODULE] Module '\windows\system32\apisetschema.dll' (6b8a8a45) just loaded at 0x000007feff480000 in process 'chrome.exe' (pid = 1664)
winvad.c : 2745 [WINVAD] VAD 0xfffffa80039b9830 found at static scan on level 4
winvad.c : 2745 [WINVAD] VAD 0xfffffa8003697010 found at static scan on level 2
winvad.c : 2745 [WINVAD] VAD 0xfffffa8004852cc0 found at static scan on level 4
winvad.c : 2745 [WINVAD] VAD 0xfffffa8003b30110 found at static scan on level 3
winselfmap.c : 749 [INFO] Protecting self-mapping entry for process chrome.exe, pid 1664 with CR3: 6fb88000, UserCR3: c4e00000 with INTEGRITY
winprocess.c : 1935 [PROCESS] 'chrome.exe' (80689a87), path \program files (x86)\google\chrome\application\chrome.exe, pid 1664, EPROCESS 0xfffffa800395b620, CR3 0x000000006fb88000, UserCR3 0x00000000c4e00000, parent at 0xfffffa8005d053e0/0xfffffa8005d053e0; not system, not agent.
winvad.c : 2081 [WINVAD] VAD for range [0x0000000000050000, 0x0000000000050000] found at 0xfffffa8003841ec0. Tries: 0
winuser_checks.c : 388 [PROCESS] 'chrome.exe' with EPROC: 0xfffffa800395b620 is fully initialized!
```

If we try to run `mimikatz` and steal some credential, we should see an alert:

```text
winummodule.c : 1126 [MODULE] Module '\users\bitlocal\downloads\mimikatz_trunk\x64\mimikatz.exe' (c157779c) just loaded at 0x000000013f1f0000 in process 'mimikatz.exe' (pid = 3512)
winummodule.c : 1149 [INFO] Application '\users\bitlocal\downloads\mimikatz_trunk\x64\mimikatz.exe' was not found among the protected ones, will remove protection.
winprocess.c : 1935 [PROCESS] 'mimikatz.exe' (e11c7971), path \users\bitlocal\downloads\mimikatz_trunk\x64\mimikatz.exe, pid 3512, EPROCESS 0xfffffa8003742060, CR3 0x0000000059398000, UserCR3 0x0000000059396000, parent at 0xfffffa80037b97f0/0xfffffa80037b97f0; not system, not agent.
exceptions_user.c : 703 Originator-> Process: (mimikatz.exe   [0xe11c7971], fffffa8003742060, 0000000059398000, 3512, F10, PEB64: 000007fffffdf000), VA: 0000000002280040, Parent: (cmd.exe [0x49b6d361], fffffa80037b97f0, 00000000902e9000, 2768, F10, PEB64: 000007fffffdd000)
exceptions_user.c : 853 Victim    -> Process: (lsass.exe      [0xadbd0ef2], fffffa8004e854e0, 0000000078d51000, 740, F19c754, SYS, PEB64: 000007fffffdd000), InjInfo: (1495040, 000007fefc830000), Init: (1, 1), Parent: (wininit.exe [0x72feee59], fffffa8004cb1700, 00000000ed68f000, 624, F19c554, SYS, PEB64: 000007fffffd9000)
exceptions_user.c : 868 Victim    -> VAD: [7fefc830000 - 7fefc99c000], Prot: 7, VadProt: 7, Type: 2, Name: \windows\system32\lsasrv.dll
exceptions_user.c : 953 Victim    -> Module: (\windows\system32\lsasrv.dll [0xd5034a27], 000007fefc830000, F848)
exceptions_user.c : 1149 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ MALWARE (user-mode) (no exc) ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
winprocess.c : 2939 [WINPROCESS] Suspicious read from lsass.exe: lsasrv.dll from process mimikatz.exe at address 2280040:1495040
winprocess.c : 2949 [ALERT] [INJECTION DETECTED] Injection took place from EPROCESS 0xfffffa8004e854e0 with CR3 0x0000000078d51000 in EPROCESS 0xfffffa8003742060 with CR3 0x0000000059398000. CR3: 0x0000000059398000, IsRead: yes
```

## Conclusions

We covered in this blog post how to quickly introspect a VM on Xen by building and running the HVMI daemon.
