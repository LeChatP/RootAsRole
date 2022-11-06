#!/bin/bash

# Check that script is executed under sudo
if [ "$SUDO_USER" = "" ]; then
    echo "Please execute this script with sudo" >&2
    exit 1
fi;

echo "Capabilities & PAM packages installation"
if [ $(which apt-get >/dev/null 2>&1 ; echo $?) -eq 0 ];then 
	apt-get install gcc llvm clang libcap2 libcap2-bin libcap-dev libcap-ng-dev libelf-dev libpam0g-dev libxml2 libxml2-dev || exit
elif [ $(which yum >/dev/null 2>&1 ; echo $?) -eq 0 ];then 
	echo "yum"
elif [ $(which pacman >/dev/null 2>&1 ; echo $?) -eq 0 ];then 
	pacman -S gcc llvm clang libcap libcap-ng libelf libxml2 linux-headers
else
	echo "Unable to find a supported package manager, exiting..."
	exit 2
fi

echo "Configuration files installation"
cp resources/sr_pam.conf /etc/pam.d/sr || exit
chmod 0644 /etc/pam.d/sr || exit
cp resources/capabilityRole.xml /etc/security || exit
echo "Define root role for the user $SUDO_USER:"
sed -i 's/ROOTADMINISTRATOR/'$SUDO_USER'/g' /etc/security/capabilityRole.xml
chmod 0644 /etc/security/capabilityRole.xml || exit
chattr +i /etc/security/capabilityRole.xml || exit

echo "configuration done. Ready to compile."
