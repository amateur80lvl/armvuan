# Armvuan

_Note: this fork is based on my local copy. The author has dropped the repository and does not respond -- amateur_

This distro is based on two prominent projects: [Armbian](https://www.armbian.com) and [Devuan](https://www.devuan.org).
It is built in the simplest way, using Devuan debootstrapped system with kernel, dtb,
u-boot, and board support packages from Armbian, thus avoiding compilation parties as much as possible.

Armvuan builder uses Armbian's toolkit but it's not a part of it as it may seem.
Actually I don't know how this pet project should evolve.
Both Armbian and Devuan have their own toolchains for ARM boards and both have fatal flaws:
the former is locked to systemd-based distros, the latter has poor support for ARM boards.

Targetted primarily to headless boards, this distro is very minimalistic
and does not run any configuration script at first boot.
After flashing your microSD card you need to make tweaks to `/etc/network/interfaces`
and write your SSH public key to `/root/.ssh/authorized_keys`.

## Dependencies

The build environment must have the following packages installed
(_as many as I managed to figure out, in addition to mine -- amateur_):
* bc
* binfmt-support
* debootstrap: messy thing, needs to be installed; TODO: check if need to clone from devuan git
* fdisk
* kpartx
* linux-base
* parallel
* parted
* qemu-user-static
* rsync
* u-boot-tools
* udev
* uuid-runtime -- for uuidgen

## Tweaks

Armvuan is shipped with the following services enabled:
* armbian-hardware-optimization
* armbian-ramlog

All the rest is up to you. You can convert necessary services
from board support package located in `/lib/systemd/system/`.
Their names start from`armbian-`.

## Troubleshooting hints

If you cannot connect to a headless board, try the following:

1. Reduce commit to a reasonable value, i.e. 6 in `/etc/fstab`
2. Disable ramlog by unlinking `/etc/rcS.d/S??armbian-ramlog`
3. Insert microSD card in and power on your board
4. Wait a couple of minutes
5. Power off, pull microSD card out and examine `/var/log`

## How to use the toolkit

* clone this repository with --recurse-submodules option
* revise `cli-armvuan.sh`
* run `prepare.sh` script to patch Armbian toolchain
* look into `armbian/config/boards` for board names
* make an image for your board:
``` bash
sudo ./armbian/compile.sh armvuan-build BOARD=orangepi-r1 BRANCH=current RELEASE=daedalus
```

Your image is here: `armbian/output/images`

## Problems

They broke u-boot at some point in past. My OrangePI 3 survived only because
I set up boot process to continue from USB HDD so upgrade failed to find the right boot device.

in dmesg output on my OrangePI 3:
```
mdio_bus stmmac-0: MDIO device at address 1 is missing.
dwmac-sun8i 5020000.ethernet end0: __stmmac_open: Cannot attach to PHY (error: -19)
```

I suspect u-boot is guilty of USB problems on NanoPI M4v2.

Remember, dist-upgrade is dangerous in Armbian.

### amateur's notes

This works. I gave it a try for `orangepizero` but I have no boards for testing yet.

To run this in [LXCex](https://github.com/amateur80lvl/lxcex) I had to create "super-privileged" container
with entire `/dev` bound-mounted in it. Otherwise, with autodev, such devices as `/dev/loop2p1` appeared
on the host system, not in container. The following lines should be added to the container's config:
```
lxc.autodev = 0
lxc.cgroup.devices.allow = c 10:237 rwm
lxc.cgroup.devices.allow = b 7:* rwm
lxc.cgroup.devices.allow = b 259:* rwm
lxc.mount.entry = /dev dev none bind 0 0
```

You'll probably need this patch https://github.com/armbian/build/issues/7430
