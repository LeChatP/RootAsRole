#!/bin/bash

# Check that script is executed under sudo
if [ -z "${SUDO_USER}" ]; then
    echo "Please execute this script with sudo" >&2
    exit 1
fi;

DOCKER=0

while getopts "yd" opt; do
	case ${opt} in
		y ) YES="-y"
			;;
		d ) DOCKER=1
			;;
	esac
done

echo "Install Rust"
if [ $(which rustup >/dev/null 2>&1 ; echo $?) -eq 0 ];then 
	echo "rustup is installed"
else
	curl https://sh.rustup.rs -sSf | sh
fi

echo "Capabilities & PAM packages installation"
if [ $(which apt-get >/dev/null 2>&1 ; echo $?) -eq 0 ];then 
	cargo install --no-default-features --force cargo-make
	apt-get install "${YES}" gcc llvm clang libcap2 libcap2-bin libcap-dev libcap-ng-dev libelf-dev libpam0g-dev libxml2 libxml2-dev make linux-headers-$(uname -r)
	if [ -n "${TEST}" ]; then
		echo "no more need to install criterion-dev" >/dev/null
	fi;
	if [ -n "${DEBUG}" ]; then
		apt-get install "${YES}" gdb
	fi;
	if [ -n "${COV}" ]; then
		apt-get install "${YES}" gcovr
	fi;
elif [ $(which yum >/dev/null 2>&1 ; echo $?) -eq 0 ];then 
	cargo install --no-default-features --force cargo-make
elif [ $(which pacman >/dev/null 2>&1 ; echo $?) -eq 0 ];then 
	pacman -S "${YES}" cargo-make gcc llvm clang libcap libcap-ng libelf libxml2 linux-headers linux-api-headers make
	if [ -n "${TEST}" ]; then
		echo "no more need to install criterion-dev" >/dev/null
	fi;
	if [ -n "${DEBUG}" ]; then
		pacman -S "${YES}" gdb
	fi;
	if [ -n "${COV}" ]; then
		pacman -S "${YES}" gcovr
	fi;
else
	echo "Unable to find a supported package manager, exiting..."
	exit 2
fi

export $(grep -h '^ID' /etc/*-release)

echo "Configuration files installation"
echo "id : ${ID}"
if [ "${ID}" == "arch" ]; then
	cp resources/arch_sr_pam.conf /etc/pam.d/sr || exit;
elif [ "${ID}" == "ubuntu" ] || [ "${ID}" == "debian" ]; then
	cp resources/deb_sr_pam.conf /etc/pam.d/sr || exit;
elif [ "${ID}" == "centos" ] || [ "${ID}" == "fedora" ]; then
	cp resources/rh_sr_pam.conf /etc/pam.d/sr || exit;
else
	echo "Unable to find a supported distribution, exiting..."
	exit 3
fi
if [ -e "/etc/security/rootasrole.xml" ];then
	read -r -p "Reconfigure policy? [y/N] " response
	case "$response" in
		[yY][eE][sS]|[yY]) 
			chattr -i /etc/security/rootasrole.xml
			;;
	esac
fi
chmod 0644 /etc/pam.d/sr || exit
cp resources/rootasrole.xml /etc/security || exit
echo "Define root role for the user ${SUDO_USER}:"
sed -i "s/ROOTADMINISTRATOR/${SUDO_USER}/g" /etc/security/rootasrole.xml
chmod 0640 /etc/security/rootasrole.xml || exit
if [ $DOCKER -eq 0 ]; then
	chattr +i /etc/security/rootasrole.xml || exit
fi


echo "configuration done. Ready to compile."
