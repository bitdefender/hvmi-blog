---
layout: post
title:  "Manually adding an exception using the introspection log"
date:   2020-08-19 13:00:00 +0300
---

## Overview

Hypervisor-based Memory Introspection (HVMI) works by blocking malicious attempts to access protected resources – for example, it may block a write access inside a protected code region, or it may block an execution attempt from a protected data page. However, sometimes legitimate software may generate accesses that look like potential attacks. To avoid classifying those accesses as malicious, HVMI contains an exception engine which can white-list specific actions, and thus allow them to occur normally, without blocking them or generating an alert. The exceptions engine within HVMI works with a binary file, which contains all the exceptions and all the signatures, which are generated from JSON files using a dedicated script. In this post, we will see how we can use the introspection log file to create such exception signatures for some legitimate accesses by detailing the format of an exception, the different types of exceptions, the signatures that can be added for each exception and how to generate the binary exceptions file.

For every violation, the exception mechanism dumps information regarding the event. Given the fact that there are several types of violations, the information about them looks different. As an example, the following violation alert is given and will be used in this tutorial:

```text
exceptions_user.c : 775 Originator-> Module: (\windows\system32\ntdll.dll      [0xbe9d4ec5], 00007ffc48640000, F18d9, VerInfo: a52b7c6a:1f0000), RIP 00007ffc48660ab5, Process: (chrome.exe [0x80689a87], ffffdf0f4ff18080, 0000000052ef2002, 7472, F185054, PEB64: 000000cb50b1d000, CLI:`"c:\program files (x86)\google\chrome\application\chrome.exe" --type=utility --field-trial-handle=1576,18443724094732229058,11877464357578631976,131072 --lang=ro --service-sandbox-type=network --enable-audio-service-sandbox --mojo-platform-channel-handle=1808 /prefetch:8`), MOV       byte ptr [rdx+rcx], al
exceptions_user.c : 1070 Victim    -> Module: (\windows\system32\kernel32.dll  [0x72f47653], 00007ff93fd80000, F14d9, VerInfo: afdeac32:b2000, IAT: 77160:2a08), Exports (1) : ['CreateFileA'], Delta: +00, , Address: (00007ff93fda1df0, 000000000d6bddf0), WriteInfo: (1, 00000000000000ff -> 0000000000000042), Flags: CODE (0x10000004)
exceptions_user.c : 1145 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ MALWARE (no exc) ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
codeblocks.c : 1223 [CODEBLOCKS] 0x1824fcdc (0xb75,      CALL), 0x6a29e179 (0xb8a,       JMP), 0xdb9caf40 (0xb8f,   MOV MEM), 0x067d0cdb (0xb93,   MOV MEM), 0x8f73c698 (0xb9c,   MOV MEM), 0x2ac21fb4 (0xba9,   MOV MEM), 0xcb5b54f8 (0xbad,   MOV MEM), 0xd89af900 (0xbcd,       JMP)
codeblocks.c : 1223 [CODEBLOCKS] 0x85f0e556 (0xbcf,   MOV MEM), 0x85f0e556 (0xbd3,   MOV MEM), 0x8b2b6d64 (0xbe1,   MOV MEM), 0x4d296f5e (0xbe5,   MOV MEM), 0x8be3b4ee (0xbea,   MOV MEM), 0x4044cdb9 (0xbed,   MOV MEM), 0xbb5b26a5 (0xbf1,   MOV MEM), 0xafa16501 (0xbfa,   MOV MEM)
codeblocks.c : 1223 [CODEBLOCKS] 0x70d57081 (0xc09,   MOV MEM), 0x93c05fb3 (0xc1f,   MOV MEM), 0x5586c31b (0xc23,   MOV MEM), 0x8d4dae5d (0xc2d,   MOV MEM), 0x9eec80ed (0xc47,   MOV MEM), 0x4051c28d (0xc4f,       JMP), 0x6166e166 (0xc51,   MOV MEM), 0x4318aae0 (0xc5e,   MOV MEM)
codeblocks.c : 1223 [CODEBLOCKS] 0xa9ef9392 (0xc62,   MOV MEM), 0xf9001597 (0xc66,   MOV MEM), 0xfdd799f6 (0xc79,   MOV MEM), 0xf143a409 (0xc89,      CALL), 0x15f293a9 (0xc93,      CALL), 0x4a4bb2a5 (0xc99,   MOV MEM), 0x3882ac1d (0xc9d,   MOV MEM), 0x8496e619 (0xca7,   MOV MEM)
codeblocks.c : 1223 [CODEBLOCKS] 0xf44006dc (0xcab,   MOV MEM), 0x87cb125f (0xcb6,   MOV MEM), 0xf2f5ee37 (0xcba,   MOV MEM), 0x7d005e31 (0xcd5,      CALL), 0xc3f06b88 (0xcea,       JMP), 0xf15a5d5e (0xcef,       JMP), 0x14093746 (0xd13,   MOV MEM), 0x960d84d2 (0xd18,      CALL)
codeblocks.c : 1223 [CODEBLOCKS] 0xac8521e5 (0xd24,   MOV MEM), 0xd96afa96 (0xd2c,       JMP), 0x9c9d2324 (0xd2e,   MOV MEM), 0xac304108 (0xd3b,   MOV MEM), 0x83dbeece (0xd5e,   MOV MEM), 0x7b22d52b (0xd63,      CALL), 0x5d9b944a (0xd6f,   MOV MEM), 0xe62ee2fe (0xd77,       JMP)
codeblocks.c : 1223 [CODEBLOCKS] 0xdfcb8e56 (0xd79,   MOV MEM), 0x657f3723 (0xd86,   MOV MEM), 0x113adedf (0xd93,   MOV MEM), 0x656219a2 (0xda4,   MOV MEM), 0x588b033b (0xdb3,   MOV MEM), 0x2f27d2ef (0xdb8,      CALL), 0x3bc0e26d (0xdbe,   MOV MEM), 0x34453c75 (0xdc6,       JMP)
codeblocks.c : 1223 [CODEBLOCKS] 0x45a6563e (0xdc8,   MOV MEM), 0xc882d2bd (0xdd4,   MOV MEM), 0x52b0458f (0xddc,   MOV MEM), 0x876320d4 (0xe00,   MOV MEM), 0x1f4dc525 (0xe05,      CALL), 0x7b4b76c5 (0xe0f,      CALL), 0x792616a5 (0xe15,   MOV MEM), 0xa1b89003 (0xe1d,   MOV MEM)
codeblocks.c : 1223 [CODEBLOCKS] 0x7e00e146 (0xe21,   MOV MEM), 0x96678d04 (0xe26,   MOV MEM), 0xbc61a665 (0xe3e,      CALL), 0x38e54615 (0xe53,       JMP), 0x71c42fb8 (0xe58,   MOV MEM), 0xc2b61ee3 (0xe5d,   MOV MEM), 0x3ebce4ae (0xe62,      CALL), 0xb59dddb1 (0xe81,      CALL)
codeblocks.c : 1223 [
0x7523d86d (CODEBLOCKS] 0x598745bd (0xe96,       JMP), 0x41dd760b (0xea4,   MOV MEM), 0x09e7b436 (0xead,   MOV MEM), 0xe076073b (0xec3,   MOV MEM), 0x85ffca8e (0xee3,       JMP), 0xa6ad5025 (0xeee,   MOV MEM), 0xc56695c2 (0xf05,   MOV MEM), (    RIP->0x00007ff9118c1f0a), 0x7c09ac49 (0xf0a,   MOV MEM)
codeblocks.c : 1223 [CODEBLOCKS] 0xe9f50e48 (0xf16,   MOV MEM), 0x7f93ddde (0xf1f,   MOV MEM), 0x66698d7c (0xf2e,   MOV MEM), 0x7bdb656e (0xf54,   MOV MEM), 0xad0c7648 (0xf5c,       JMP), 0xfd82ba7b (0xf5e,   MOV MEM), 0x595e9ac6 (0xf6b,   MOV MEM), 0xf6f,       JMP)
codeblocks.c : 1283 [CODEBLOCKS] 0x568ba88c (0xf71,   MOV MEM), 0xe7cb7946 (0xf7f,   MOV MEM), 0x9825ceae (0xf89,   MOV MEM), 0x368b4a53 (0xf94,   MOV MEM), 0x876320d4 (0xfa1,   MOV MEM), 0x1f4dc525 (0xfa6,      CALL)
```

## The format of an exception

```json
{
    "Type": "<exception type> ",
    "Exceptions": [
        {
            "process": "<the process in which the violation took place>",
            "originator": "<the originator of the violation>",
            "victim": "<the victim of the violation>",
            "object_type": "<the type of the modified zone>",
            "flags": "<the flags of the exception>"
            "signatures": [
                  "<signature id 1>", "<signature id 2>", … "<signature id n>"
            ]
        }
    ]
}
```

### The type of the violation

There are three types of violations: *user-mode*, *kernel-mode* and *kernel-user mode*. The violation type can be found in the following line:

```text
exceptions_user.c : 1145 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ MALWARE (user-mode) (no exc)^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

It can be seen that the violation type is `user-mode`, thus the `<exception type>` is `user` and the field will be the following: `"Type": "user "`.

The reason why a violation was not excepted is given by the keyword after the violation type (`no exc` in this case):

|Reason             |Description                                                        |
|-------------------|-------------------------------------------------------------------|
|no exc             | No exceptions were found for the alert for violation.             |
|extra              | Extra checks failed.                                              |
|error              | An error occurred in the exception mechanism.                     |
|no sig             | The codeblocks signature did not match.                           |
|value              | The value signature did not match.                                |
|value code         | The value-code signature did not match.                           |
|export             | The export signature did not match.                               |
|idt                | The IDT signature did not match.                                  |
|version os         | The operating-system version signature did not match.             |
|version intro      | The introcore version signature did not match.                    |
|process creation   | The process-creation signature did not match.                     |

### The originator/process

The following line contains the information about the originator of the violation and about the process in which the violation took place:

```text
exceptions_user.c : 775 Originator-> Module: (\windows\system32\ntdll.dll      [0xbe9d4ec5], 00007ffc48640000, F18d9, VerInfo: a52b7c6a:1f0000), RIP 00007ffc48660ab5, Process: (chrome.exe [0x80689a87], ffffdf0f4ff18080, 0000000052ef2002, 7472, F185054, PEB64: 000000cb50b1d000, CLI:`"c:\program files (x86)\google\chrome\application\chrome.exe" --type=utility --field-trial-handle=1576,18443724094732229058,11877464357578631976,131072 --lang=ro --service-sandbox-type=network --enable-audio-service-sandbox --mojo-platform-channel-handle=1808 /prefetch:8`), MOV       byte ptr [rdx+rcx], al
```

As can be seen the violation originator is the user-mode module `\windows\system32\ntdll.dll` and the violation took place in the `chrome.exe` process. The exception mechanism does not use the full path of the module/process involved in the violation, but only its name. Therefore the `<process>` and `<originator>` fields will be the following: `"originator": "ntdll.dll"` and `"process": "chrome.exe"`.

### The victim

The following line contains the information about the victim name and the violated memory region:

```text
exceptions_user.c : 1070 Victim    -> Module: (\windows\system32\kernel32.dll  [0x72f47653], 00007ff93fd80000, F14d9, VerInfo: afdeac32:b2000, IAT: 77160:2a08), Exports (1) : ['CreateFileA'], Delta: +00, , Address: (00007ff93fda1df0, 000000000d6bddf0), WriteInfo: (1, 00000000000000ff -> 0000000000000042), Flags: CODE (0x10000004)
```

As can be seen the victim of the violation is user-mode module `\windows\system32\kernel32.dll`. The exception mechanism does not use the full path of the module/process involved in the violation, but only its name. Therefore the `<victim>` field will be the following: `"victim": "kernel32.dll"`.

### The object type

The following line contains the information about the violated memory region:

```text
exceptions_user.c : 1070 Victim    -> Module: (\windows\system32\kernel32.dll  [0x72f47653], 00007ff93fd80000, F14d9, VerInfo: afdeac32:b2000, IAT: 77160:2a08), Exports (1) : ['CreateFileA'], Delta: +00, , Address: (00007ff93fda1df0, 000000000d6bddf0), WriteInfo: (1, 00000000000000ff -> 0000000000000042), Flags: CODE (0x10000004)
```

As can be seen the victim of the violation is user-mode module `\windows\system32\kernel32.dll`. Therefore, the object type for module violation is `"module"`, but the Flags field contains more precise information about the zone type - `CODE (0x10000004)`, i.e. the memory area that contains the code. For this memory zone, there is a specific object type: `"module code"`. The `"object_type”` field will be the following `"object_type": "module code"`.

NOTE: The object type `"module"` includes all other `" module <zone type>"` objects.

### The flags

The exception flags contain extra information about the violation, such as violation type (read/write/exec), operating mode (32/64), operating system (linux for Linux guest; default is for Windows guest). In our case the violation type is given by the field `WriteInfo: (1, 00000000000000ff -> 0000000000000042)` (see information about victim), and the operating mode is `64`. Therefore the `<flags>` field will be the following: `"flags": "write 64"`.

NOTE: If the violation type is missing, the `"write"` flag is used; if the operating mode is missing, the `"32 64"` flags are used.

### The exception

Having all the necessary information, the exception will be the following:

```json
{
    "Type": "user",
    "Exceptions": [
        {
            "process": "chrome.exe",
            "originator": "ntdll.dll"
            "victim": "kernel32.dll”
            "object_type": "module code”,
            "flags": "write 64”
            "signatures": [
            ]
        }
    ]
}
```

It is recommended to make new files for exceptions; we will use an exception file called `exceptions.json`.

## The format of a signature

```json
{
    "sig_type": <the type of the signature>,
    "sig_id": <uniq id>,
    "flags" : < the flags of the exception >,
    <signature specific data>
}
```

For this violation, we will put two signatures: one on export and one on codeblocks; these can be used because we have the necessary information. The export signature can be used because the violation modified code from an export of kernel32.dll and the codeblocks signature can be used for almost all types of violation, as the codeblocks are hashes computed on the code that triggered the violation.

### The export signature format

```json
{
    "Type": "<signature type> ",
    "Signatures": [
        {
            "sig_type": "export",
            "sig_id": "<id>",
            "library": "<library name>",
            "hashes": [
                {
                    "name": "<function name 1>",
                    "delta": <delta 1>
                },
                {
                    "name": "<function name 2>",
                    "delta": <delta 2>
                },
                …
                {
                    "name": "<function name n>",
                    "delta": <delta n>
                }
            ]
        }
    ]
}
```

It is recommended to make new files for signatures; we will use a file that contains export-signatures called `export-signatures.json`.

The `<signature type>` field must be the same with the exception type. The following line contains the information required for an export signature:

```text
exceptions_user.c : 1070 Victim    -> Module: (\windows\system32\kernel32.dll  [0x72f47653], 00007ff93fd80000, F14d9, VerInfo: afdeac32:b2000, IAT: 77160:2a08), Exports (1) : ['CreateFileA'], Delta: +00, , Address: (00007ff93fda1df0, 000000000d6bddf0), WriteInfo: (1, 00000000000000ff -> 0000000000000042), Flags: CODE (0x10000004)
```

#### The library name

As can be seen the modified library name is user-mode module `\windows\system32\kernel32.dll`. The exception mechanism does not use the full path of the library involved in the violation, but only its name. Therefore the `<library>` field will be the following: `"library": "kernel32.dll"`.

#### The hashes list

The hashes field contains a list of pairs that contain the name of modified function name (name) and the number of bytes modified from the beginning of the function (delta). In the line above there is the Exports field that contains a list of function names `Exports (1) : ['CreateFileA']`. When the modified functions are dumped, a memory range of 0x20 is taken into account, because more functions may be modified by this violation. In most cases, only the first function name in the array is considered for adding the signature.

The line above also contains a field named Delta that contains the offset from the beginning of the function from which it was modified `Delta: +00` (in this case the modification was made at the beginning of the function). To compute the delta field of signature, the `WriteInfo: (1, 00000000000000ff -> 0000000000000042)` field from the log line is required. Thus, we will allow the modification of a byte from the beginning of the `CreateFileA` function.

#### The codeblocks signature flags

The codeblocks signature flags contain information about the operating mode (32/64) and the operating system (Linux used for Linux guest; default is for Windows guest). The operating mode flags of the signature must be the same with the operating mode flags of the exception.

#### The export signature

Having all the necessary information, the signature will be the following:

```json
{
    "Type": "user",
    "Signatures": [
        {
            "sig_type": "export",
            "sig_id": "export-signature",
            "library": "kernel32.dll ",
            "flags": "64",
            "hashes": [
                {
                    "name": "CreateFileA",
                    "delta": 1
                }
            ]
        }
    ]
}
```

### The codeblocks signature format

```json
{
    "Type": "<signature type> ",
    "Signatures": [
        {
            "sig_type": "codeblocks",
            "sig_id": "<id>",
            "score": <the number of codeblocks that needs to be matched>,
            "hashes": [
                [" hash1", " hash2" , ... " hash n "],
                ...
                [" hash1", " hash2" , ... " hash n "]
            ]
        }
    ]
}
```

It is recommended to make new files for signatures; we will use a file that contains export-signatures called `codeblocks-signatures.json`. The `<signature type>` field must be the same with the exception type.

#### The codeblocks hashes list

A hash (or codeblock) is a cyclic redundancy check of a group of instructions. The exception mechanism extracts codeblocks around the IP of the Originator. The following lines contains the extracted codeblocks:

```text
codeblocks.c : 1223 [CODEBLOCKS] 0x1824fcdc (0xb75,      CALL), 0x6a29e179 (0xb8a,       JMP), 0xdb9caf40 (0xb8f,   MOV MEM), 0x067d0cdb (0xb93,   MOV MEM), 0x8f73c698 (0xb9c,   MOV MEM), 0x2ac21fb4 (0xba9,   MOV MEM), 0xcb5b54f8 (0xbad,   MOV MEM), 0xd89af900 (0xbcd,       JMP)
codeblocks.c : 1223 [CODEBLOCKS] 0x85f0e556 (0xbcf,   MOV MEM), 0x85f0e556 (0xbd3,   MOV MEM), 0x8b2b6d64 (0xbe1,   MOV MEM), 0x4d296f5e (0xbe5,   MOV MEM), 0x8be3b4ee (0xbea,   MOV MEM), 0x4044cdb9 (0xbed,   MOV MEM), 0xbb5b26a5 (0xbf1,   MOV MEM), 0xafa16501 (0xbfa,   MOV MEM)
codeblocks.c : 1223 [CODEBLOCKS] 0x70d57081 (0xc09,   MOV MEM), 0x93c05fb3 (0xc1f,   MOV MEM), 0x5586c31b (0xc23,   MOV MEM), 0x8d4dae5d (0xc2d,   MOV MEM), 0x9eec80ed (0xc47,   MOV MEM), 0x4051c28d (0xc4f,       JMP), 0x6166e166 (0xc51,   MOV MEM), 0x4318aae0 (0xc5e,   MOV MEM)
codeblocks.c : 1223 [CODEBLOCKS] 0xa9ef9392 (0xc62,   MOV MEM), 0xf9001597 (0xc66,   MOV MEM), 0xfdd799f6 (0xc79,   MOV MEM), 0xf143a409 (0xc89,      CALL), 0x15f293a9 (0xc93,      CALL), 0x4a4bb2a5 (0xc99,   MOV MEM), 0x3882ac1d (0xc9d,   MOV MEM), 0x8496e619 (0xca7,   MOV MEM)
codeblocks.c : 1223 [CODEBLOCKS] 0xf44006dc (0xcab,   MOV MEM), 0x87cb125f (0xcb6,   MOV MEM), 0xf2f5ee37 (0xcba,   MOV MEM), 0x7d005e31 (0xcd5,      CALL), 0xc3f06b88 (0xcea,       JMP), 0xf15a5d5e (0xcef,       JMP), 0x14093746 (0xd13,   MOV MEM), 0x960d84d2 (0xd18,      CALL)
codeblocks.c : 1223 [CODEBLOCKS] 0xac8521e5 (0xd24,   MOV MEM), 0xd96afa96 (0xd2c,       JMP), 0x9c9d2324 (0xd2e,   MOV MEM), 0xac304108 (0xd3b,   MOV MEM), 0x83dbeece (0xd5e,   MOV MEM), 0x7b22d52b (0xd63,      CALL), 0x5d9b944a (0xd6f,   MOV MEM), 0xe62ee2fe (0xd77,       JMP)
codeblocks.c : 1223 [CODEBLOCKS] 0xdfcb8e56 (0xd79,   MOV MEM), 0x657f3723 (0xd86,   MOV MEM), 0x113adedf (0xd93,   MOV MEM), 0x656219a2 (0xda4,   MOV MEM), 0x588b033b (0xdb3,   MOV MEM), 0x2f27d2ef (0xdb8,      CALL), 0x3bc0e26d (0xdbe,   MOV MEM), 0x34453c75 (0xdc6,       JMP)
codeblocks.c : 1223 [CODEBLOCKS] 0x45a6563e (0xdc8,   MOV MEM), 0xc882d2bd (0xdd4,   MOV MEM), 0x52b0458f (0xddc,   MOV MEM), 0x876320d4 (0xe00,   MOV MEM), 0x1f4dc525 (0xe05,      CALL), 0x7b4b76c5 (0xe0f,      CALL), 0x792616a5 (0xe15,   MOV MEM), 0xa1b89003 (0xe1d,   MOV MEM)
codeblocks.c : 1223 [CODEBLOCKS] 0x7e00e146 (0xe21,   MOV MEM), 0x96678d04 (0xe26,   MOV MEM), 0xbc61a665 (0xe3e,      CALL), 0x38e54615 (0xe53,       JMP), 0x71c42fb8 (0xe58,   MOV MEM), 0xc2b61ee3 (0xe5d,   MOV MEM), 0x3ebce4ae (0xe62,      CALL), 0xb59dddb1 (0xe81,      CALL)
codeblocks.c : 1223 [CODEBLOCKS] 0x598745bd (0xe96,       JMP), 0x41dd760b (0xea4,   MOV MEM), 0x09e7b436 (0xead,   MOV MEM), 0xe076073b (0xec3,   MOV MEM), 0x85ffca8e (0xee3,       JMP), 0xa6ad5025 (0xeee,   MOV MEM), 0xc56695c2 (0xf05,   MOV MEM), (    RIP->0x00007ff9118c1f0a), 0x7c09ac49 (0xf0a,   MOV MEM)
codeblocks.c : 1223 [CODEBLOCKS] 0xe9f50e48 (0xf16,   MOV MEM), 0x7f93ddde (0xf1f,   MOV MEM), 0x66698d7c (0xf2e,   MOV MEM), 0x7bdb656e (0xf54,   MOV MEM), 0xad0c7648 (0xf5c,       JMP), 0xfd82ba7b (0xf5e,   MOV MEM), 0x595e9ac6 (0xf6b,   MOV MEM), 0x7523d86d (0xf6f,       JMP)
codeblocks.c : 1283 [CODEBLOCKS] 0x568ba88c (0xf71,   MOV MEM), 0xe7cb7946 (0xf7f,   MOV MEM), 0x9825ceae (0xf89,   MOV MEM), 0x368b4a53 (0xf94,   MOV MEM), 0x876320d4 (0xfa1,   MOV MEM), 0x1f4dc525 (0xfa6,      CALL)
```

Given the fact that in most cases a lot of codeblocks are dumped, it is recommended to put a number of codeblocks bigger than 4 per list of hashes, and there should be around the IP `(RIP->0x00007ff9118c1f0a)`. For this violation we’ll select 8 codeblocks (marked on the above lines).

#### Codeblocks signature flags

The codeblocks signature flags contain information about the operating mode (32/64), the extraction level (medium used only for kernel-mode violations) and the operating system (linux used for Linux guest; default is for Windows guest). The operating mode flags of the signature must be the same with the operating mode flags of the exception.

#### The codeblocks signature

Having all the necessary information, the signature will be the following:

```json
{
    "Type": "user",
    "Signatures": [
        {
            "sig_type": "codeblocks",
            "sig_id": "codeblocks-signature",
            "score": 6,
            "flags": "64"
            "hashes": [
                   ["0xe076073b", "0x85ffca8e", "0xa6ad5025", "0xc56695c2", "0x7c09ac49" , "0xe9f50e48", "0x7f93ddde ", "0x66698d7c"]
            ]
        }
    ]
}
```

## The final exception

The final exception will contain the two signatures - codeblocks and exports:

```json
{
    "Type": "user",
    "Exceptions": [
        {
            "process": "chrome.exe",
            "originator": "ntdll.dll"
            "victim": "kernel32.dll”
            "object_type": "module code”,
            "flags": "write 64”
            "signatures": [
                "codeblocks-signature",
                "export-signature"
            ]
        },
    ]
}
```

## Generate the exceptions binary file

To generate the exceptions binary, the scripts from `hvmi/exceptions` directory is used. The command line is the following:

```json
python3 exceptions.py --build=0 --verbose=2 exceptions.json codeblocks-signatures.json export-signatures.json --output exceptions.bin
```

The binary file will be loaded by the introspection engine. If you wish to test this with the hvmid daemon, check out the `exceptionsFile` value inside `hvmi/daemon/settings.json.in`, and place the `exceptions.bin` file in the location indicated by that field.
