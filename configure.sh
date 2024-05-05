#!/bin/bash

DOCKER=0

while getopts "yd" opt; do
	case ${opt} in
		y ) YES="-y"
			;;
		d ) DOCKER=1
			;;
	esac
done

if [ -z ${SUDO_USER+x} ]; then INSTALL_USER=`id -urn`; else INSTALL_USER=$SUDO_USER; fi

if [ $(capsh --has-p=CAP_DAC_OVERRIDE; echo $?) != 0 ] || ( [ ${DOCKER} -eq 0 ] && [ $(capsh --has-p=CAP_LINUX_IMMUTABLE; echo $?) != 0 ] ) ; then
    echo "Vous avez besoin des capacités CAP_DAC_OVERRIDE et CAP_LINUX_IMMUTABLE pour exécuter ce script."
    exit 1
fi

export $(grep -h '^ID' /etc/*-release)

echo "Configuration files installation"
echo "id : ${ID}"
if [ "${ID}" == "arch" ]; then
    cp resources/arch_sr_pam.conf /etc/pam.d/sr || exit;
elif [ "${ID}" == "ubuntu" ] || [ "${ID}" == "debian" ]; then
    cp resources/deb_sr_pam.conf /etc/pam.d/sr || exit;
elif [ "${ID}" == "centos" ] || [ "${ID}" == "fedora" ] || [[ "${ID}" == *"rhel"* ]]; then
    cp resources/rh_sr_pam.conf /etc/pam.d/sr || exit;
else
    echo "Unable to find a supported distribution, exiting..."
    exit 3
fi



if [ -e "/etc/security/rootasrole.json" ];then
	if [ $INSTALL_USER == "0" ]; then
		echo "Warning: You run this script as real root, so the administator role is defined for the root user"
	fi
	read -r -p "Reconfigure policy? [y/N] " response
	case "$response" in
		[yY][eE][sS]|[yY]) 
			if [  $DOCKER -eq 0 ]; then # Docker does not support immutable
				chattr -i /etc/security/rootasrole.json
			fi
			cp resources/rootasrole.json /etc/security || exit
			echo "Define root role for the user $INSTALL_USER"
			sed -i "s/ROOTADMINISTRATOR/$INSTALL_USER/g" /etc/security/rootasrole.json
			;;
	esac
else 
	cp resources/rootasrole.json /etc/security || exit
	echo "Define root role for the user $INSTALL_USER"
	sed -i "s/ROOTADMINISTRATOR/$INSTALL_USER/g" /etc/security/rootasrole.json
fi
chmod 0644 /etc/pam.d/sr || exit
chmod 0640 /etc/security/rootasrole.json || exit
if [  $DOCKER -eq 0 ]; then
	chattr +i /etc/security/rootasrole.json || exit
fi

echo "Configuration done, Ready to compile."
