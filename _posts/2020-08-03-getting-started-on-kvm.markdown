---
layout: post
title:  "HVMI demo setup on KVM"
date:   2020-08-10 11:53:00 +0300
---

For a Xen guide check [HVMI demo setup on Xen](/blog/2020/08/10/getting-started-on-Xen.html).

Packer templates can be found in the [kvmi-templates](https://github.com/mdontu/kvmi-templates) repository.

## High level plan

* Install Ubuntu Linux 20.04 on the host
  * Install the kernel build dependencies
  * Install the KVMI enabled kernel
  * Install libvirt for KVM
* Create an Ubuntu Linux 20.04 guest VM
  * Install the kernel build dependencies
  * Install the KVMI enabled kernel
  * Install libkvmi
  * Install libbdvmi
  * Install HVMI (introcore, exceptions, CAMI, hvmid)
* Install the KVMI enabled qemu
* Reconfigure the Ubuntu Linux 20.04 guest VM to enable KVMI
* Install a target (Windows, Linux) guest VM
* Reconfigure the target guest to enable KVMI
* Power on the Ubuntu Linux 20.04 guest VM
  * Start the demo application (hvmid)
* Power on the target guest VM

## Install Ubuntu Linux 20.04 on the host

### Install the kernel build dependencies

Prepare the build environment using this [official documentation](https://wiki.ubuntu.com/Kernel/BuildYourOwnKernel).

### Install the KVMI enabled kernel

```shell
git clone https://github.com/KVM-VMI/kvm.git
git checkout kvmi-v7
make oldconfig
scripts/config --enable KVM_INTROSPECTION
scripts/config --enable KVM_INTROSPECTION_GUEST
scripts/config --enable REMOTE_MAPPING
scripts/config --disable CONFIG_KSM
scripts/config --disable TRANSPARENT_HUGEPAGE
make
sudo su
INSTALL_MOD_STRIP=1 make modules_install
make install
update-grub
```

Create the file `/etc/modules-load.d/vhost-vsock.conf` with the following contents:

```text
vhost-vsock
```

Create the file `/etc/udev/rules.d/10-vhost-vsock.rules` with the following contents:

```text
KERNEL=="vhost-vsock", GROUP="kvm", MODE="0660"
```

Then update all initrd images:

```shell
sudo update-initramfs -k all -u
```

Now you should reboot into the new kernel.

### Install libvirt for KVM

```shell
sudo apt install libvirt-daemon libvirt-daemon-system libvirt-daemon-system-systemd
```

## Create an Ubuntu Linux 20.04 guest VM

### Install the kernel build dependencies

Prepare the build environment using this [official documentation](https://wiki.ubuntu.com/Kernel/BuildYourOwnKernel).

### Install the KVMI enabled kernel

```shell
git clone https://github.com/KVM-VMI/kvm.git
git checkout kvmi-v7
make oldconfig
scripts/config --enable KVM_INTROSPECTION
scripts/config --enable KVM_INTROSPECTION_GUEST
scripts/config --enable REMOTE_MAPPING
scripts/config --disable CONFIG_KSM
scripts/config --disable TRANSPARENT_HUGEPAGE
make
sudo su
INSTALL_MOD_STRIP=1 make modules_install
make install
update-grub
```

### Install libkvmi

```shell
git clone https://github.com/bitdefender/libkvmi.git
cd libkvmi
./bootstrap
mkdir build
cd build
../configure --prefix=/usr/local --enable-optimize
make
sudo make install
```

### Install libbdvmi

```shell
sudo apt install libboost-all-dev libxen-dev pkg-config uuid-dev
git clone https://github.com/bitdefender/libbdvmi.git
cd libbdvmi
./bootstrap
mkdir build
cd build
../configure --prefix=/usr/local --enable-kvmi --enable-optimize
make
sudo make install
```

### Install hvmi

```shell
sudo apt install cmake libjsoncpp-dev
git clone https://github.com/hvmi/hvmi.git
cd hvmi
git submodule init
git submodule update
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
cd ../daemon
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```

Edit the configuration file `/usr/local/etc/hvmid/settings.json` and set `kvmBackend` to true.

You should poweroff the VM at this point as we will reconfigure it later.

## Install the KVMI enabled qemu

```shell
sudo apt build-dep qemu-kvm
git clone https://github.com/KVM-VMI/qemu.git
git checkout kvmi-v7
mkdir build
cd build
../configure --prefix=/usr/local --python=`which python3` --target-list=x86_64-softmmu --disable-werror
make
sudo make install
```

Edit `/etc/libvirt/qemu.conf` and uncomment then modify `cgroup_device_acl` to allow access to `vhost-vsock`:

```text
cgroup_device_acl = [
	"/dev/null", "/dev/full", "/dev/zero",
	"/dev/random", "/dev/urandom",
	"/dev/ptmx", "/dev/kvm", "/dev/kqemu",
	"/dev/rtc", "/dev/hpet", "/dev/vfio/vfio",
	"/dev/vhost-vsock"
]
```

Restart `libvirtd` to pick up the modifications:

```shell
systemctl restart libvirtd
```

## Reconfigure the Ubuntu 20.04 guest VM to enable KVMI

Using `virsh` edit the VM configuration as follows:

* make sure the domain definition uses the XML schema `http://libvirt.org/schemas/domain/qemu/1.0`:  

  ```xml
  <domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
  ```

* make sure the machine is one supported by `/usr/local/bin/qemu-system-x86_64`:  

  ```xml
  <type arch='x86_64' machine='pc-q35-2.12'>hvm</type>
  ```

  You can see the list of supported machines with the command:

  ```shell
  /usr/local/bin/qemu-system-x86_64 -M help
  ```

* make sure the emulator is set to `/usr/local/bin/qemu-system-x86_64`:  

  ```xml
  <emulator>/usr/local/bin/qemu-system-x86_64</emulator>
  ```

* make sure qemu enables the vsock device used by hvmid by adding the following lines:  

  ```xml
  <qemu:commandline>
    <qemu:arg value='-device'/>
    <qemu:arg value='vhost-vsock-pci,id=bitdefender-vsock,guest-cid=321'/>
  </qemu:commandline>
  ```

## Install a target (Windows, Linux) guest VM

The current release of [HVMI](https://github.com/hvmi/hvmi) has support for Windows 7 (SP1, SP2), Windows 10 1809 (RS5), Ubuntu Linux 18.04 and CentOS 8. After the installation is complete, power it off as it needs to be reconfigured.

## Reconfigure the target guest to enable KVMI

Using `virsh` edit the VM configuration as follows:

* make sure the domain definition uses the XML schema `http://libvirt.org/schemas/domain/qemu/1.0`:  

  ```xml
  <domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
  ```

* make sure the machine is one supported by `/usr/local/bin/qemu-system-x86_64`:  

  ```xml
  <type arch='x86_64' machine='pc-q35-2.12'>hvm</type>
  ```

  You can see the list of supported machines with the command:

  ```shell
  /usr/local/bin/qemu-system-x86_64 -M help
  ```

* make sure the emulator is set to /usr/local/bin/qemu-system-x86_64:  

  ```xml
  <emulator>/usr/local/bin/qemu-system-x86_64</emulator>
  ```

* make sure qemu enables the vsock device used by hvmid by adding the following lines:  

  ```xml
  <qemu:commandline>
    <qemu:arg value='-chardev'/>
    <qemu:arg value='socket,id=bitdefender-socket,cid=321,port=1234,reconnect=3'/>
    <qemu:arg value='-object'/>
    <qemu:arg value='introspection,id=bitdefender-kvmi,chardev=bitdefender-socket'/>
  </qemu:commandline>
  ```

## Power on the Ubuntu 20.04 guest VM

After powering up the VM hosting HVMI we must create a dedicated policy for the target VM that we will then be starting. Grab the UUID of the target VM and then do:

```shell
sudo su -
cd /usr/local/etc/hvmid/policies/
cp default.json <uuid>.json
```

### Start the demo application (hvmid)

```shell
sudo su -
LD_LIBRARY_PATH=/usr/local/lib /usr/local/bin/hvmid --start
```

Use `--kill` to stop the daemon.

## Power on the target guest VM

Everything being in place, upon powering up the target VM `hvmid` will log in syslog a bunch of information related to the introspection process:

```shell
journalctl -t hvmid -f
```

Example:

```text
Aug 06 17:12:07 sva hvmid[1116]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] Found domain: 'win7'
Aug 06 17:12:07 sva hvmid[1116]: Loading policy file /usr/local/etc/hvmid/policies/ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e.json
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] Setting page cache limit to 512 mappings
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] The hypervisor backend has chosen a page cache limit of 512 mappings
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] Guest start time: 1596733
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] Introcore init complete
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] introcore.c : 247 IntroCore initialised: version 1.132.1, build 00049, changeset 368d5f7, built on Aug  6 2020 14:34:05 from branch master
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] MaxGPFN: 0x7ffff
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] Introcore about to be initialized with options 0x3f7eb3ffffff: km_nt km_hal km_hal_heap_exec km_hal_int_ctrl km_ssdt km_idt km_hdt km_sys_cr3 km_token km_nt_drivers>
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] Loading live update file /usr/local/share/introcore/intro_live_update.bin
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] introapi.c : 133 [INTRO-INIT] New guest notification, handle = 0x7f92e09c8580
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] introapi.c : 135 [INTRO-INIT] Will use options: 0x00003f7eb3ffffff
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] update_guests.c : 1610 [INFO] Loaded cami version 1.4 build 0
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] guests.c : 792 [INTRO-INIT] CPU_COUNT = 2
Aug 06 17:12:07 sva hvmid[1195]: [ec3eef9c-dd45-4985-ae51-e08e8b3a5d9e] guests.c : 800 [INTRO-INIT] TSC speed = 0x0000000000000000 ticks/second
```
