#!/bin/bash

tput setaf 1
echo "NOTE: This script will reboot the system if you opt to allow kernel update."
echo "      If reboot is not required, it will log you out and require re-login for new permissions to take effect."
echo ""
read -n 1 -s -r -p "Press Ctrl-c to quit, any key to continue..."
tput sgr0

logout_needed=false

sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    libpcap-dev \
    gcc-multilib \
    build-essential
sudo apt install linux-tools-$(uname -r)
sudo apt install linux-headers-$(uname -r)

git submodule update --init --recursive

kernel_ver=`uname -r`
echo "Running kernel version: $kernel_ver"
mj_ver=$(echo $kernel_ver | cut -d. -f1)
mn_ver=$(echo $kernel_ver | cut -d. -f2)

if [[ "$mj_ver" < "5" ]] || [[ "$mn_ver" < "6" ]]; then
        tput setaf 1
	echo "Arion Compute Node DP notification submodule requires an updated kernel: linux-5.6-rc2. Current version is $kernel_ver"

	read -p "Execute kernel update script (y/n)?" choice
	tput sgr0
	case "$choice" in
	  y|Y ) sh ./kernelupdate.sh;;
	  n|N ) echo "Please run kernelupdate.sh to download and update the kernel!"; exit;;
	  * ) echo "Please run kernelupdate.sh to download and update the kernel!"; exit;;
	esac
fi

if [ "$logout_needed" = true ]; then
    logout
fi
