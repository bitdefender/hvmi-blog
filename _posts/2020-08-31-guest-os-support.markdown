---
layout: default
title:  "Adding support for a new operating system"
date:   2020-08-31 11:00:00 +3
---

## Introduction

HVMI is a technology designed to offer security from outside a virtual
machine, by leveraging the hardware isolation provided by Intel VT-x. An
issue with running outside a VM is the **semantic gap**, meaning that
the Introspection engine will only be able to access raw memory with no
apparent meaning.

Intel VT-x allows the hypervisor to notify the Introspection engine on
some events (such as MSR writes, CR writes, interrupts, memory accesses,
etc.) and also query the current guest state (MSRs, CRs, IDT, GDT,
GPRs, raw memory, etc.) which help to overcome the semantic gap.

However, there's only so much information one can get by classic
introspection techniques while also maintaining a relatively low
performance impact for the guest OS. For this reason, HVMI relies on an
update file that contains important information about the guest OS that
helps extract valuable information from the raw guest bytes. 

For now, we'll talk about adding support for a guest. Please see the
[official documentation](http://hvmi.readthedocs.io) for more information about
the update file and the way HVMI interacts with it.

## Adding support for a Guest

The **cami** project in the HVMI root directory is responsible for
generating the update file. Said project is split into 3 main
directories:

- **sources**, which contains **yaml** files that contain the information needed to support a guest;

- **scripts**, which contains the codebase responsible to pack said information into a format that will later be loaded by HVMI;

- **tools** which contains a number of utilities to make life easier when adding support for a guest.

The **sources** directory already contains a couple of yaml files
that describe a number of guests. When adding support for a new guest,
the user should add a new file in this folder since this is the default
location where the generator scripts search for update files.

## Adding support for a Windows Guest

To add support for a new windows guest, the user needs to have a copy of
said guests **ntoskrnl.exe** and **ntdll.dll**. Both of these are found
in the `WINDIR:\Windows\System32` folder, where `WINDIR` is the
drive with the Windows installation (generally the C drive). Note that
the kernel image may have different names, such as **ntkrnlmp.exe**,
**ntkrnlpa.exe** or **ntkrpamp.exe**.

After acquiring those files, it's time to shift focus to the **tools**
directory, specifically to the **r2cami** directory within it.
**r2cami** is a project containing a couple of [**python 3**](https://www.python.org/downloads/) 
scripts dedicated to automating the task of adding support
for a new Windows OS. To do that, it uses existing tools such as
[**radare2**](https://rada.re/n/) and [**BitDefender Disassembler**](https://github.com/bitdefender/bddisasm).

Note that **r2cami** takes advantage of [**r2pipe**](https://github.com/radareorg/radare2-r2pipe) 
which is a collection of wrapper APIs that allow users to create scripts
such as this. If your **radare** installation did not include
**r2pipe**, please check the official **r2pipe** or **radare2**
documentation.

To generate an update file, a user should simply run **r2cami** as
demonstrated below.

```console
python r2cami.py --kernel=/path/to/ntoskrnl.exe --ntdll=/path/to/ntdll.dll --outfile=/path/to/desired/outfile
```

Now, the file at `/path/to/desired/outfile` will contain all of the
guest specific fields, function patterns and other obscure fields that
HVMI needs to successfully initialize and protect the guest.

## Adding support for a Linux Guest

To add support for a Linux guest, one needs the kernel debug symbols and 
the configuration file (which is usually located under `/boot` directory) for
the desired version. Extracting the layout of structures is done by a
GDB module that creates a new command, `all-offsets \<output-file\>`.
Running this command will create a new file containing the fields
offsets and the size of each structure. In order to import this command,
the user has to either run `gdb` from `hvmi/cami/tools/linux` directory, or
import the `offsets.py` script with the following commands sequence:

```console
(gdb) python
>gdb.execute('source hvmi/cami/tools/linux/offsets.py')
>end
```

Next, because HVMI does not need that much information, the user has to
run another script, `generate_yaml.py` which will create a yaml file that
should be placed under the `hvmi/cami/sources/linux/opaque_fields`
directory.

The following commands sequence has to be executed to generate the
support file for a kernel version, assuming `hvmi/cami/tools/linux` as
current working directory:

```console
$ gdb path/to/vmlinux
(gdb) all-offsets offsets.json
(gdb) exit
$ python3 generate_yaml.py offsets.json supported_os.yaml config-file
```

HVMI also requires a signature for the very first page from the
kernel code section. There is no tool able to generate this yet, so
this step must be done manually. The user needs to select a sequence of
bytes generic enough to not be affected by alternative changes. This
sequence should be placed in `hvmi/cami/sources/linux/dist_sigs.yaml`
file.

## Generating the binary file

Since HVMI can't parse yaml files, one needs to pack it into a format
that HVMI can understand and load. To do that, one should run the
**cami** generator script from the **scripts** folder as follows:

```console
python scripts/main.py --major 1 --minor 4 --buildnumber 0 --sources=sources
```

The **sources** argument specifies where the script will search for the
yaml files. In this case, it is the path to the folder where the
user saved the outfile generated earlier.

The other arguments are simply version control arguments. The update
file is designed to be backwards compatible. That means that HVMI
will NOT load an older file than supported, but will load a newer one.
The values specified in the examples are the current HVMI compatible
versions.

Please see the [official documentation](http://hvmi.readthedocs.io) to fully
understand the update file and the way HVMI interacts with it.
