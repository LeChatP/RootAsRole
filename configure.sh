#!/bin/bash


if [ -z ${SUDO_USER+x} ]; then INSTALL_USER=`id -urn`; else INSTALL_USER=$SUDO_USER; fi

if [ -e "/etc/security/rootasrole.json" ];then
	read -r -p "Reconfigure policy? [y/N] " response
	case "$response" in
		[yY][eE][sS]|[yY]) 
			chattr -i /etc/security/rootasrole.json
			;;
	esac
fi
chmod 0644 /etc/pam.d/sr || exit
cp resources/rootasrole.json /etc/security || exit
echo "Define root role for the user $INSTALL_USER:"
sed -i "s/ROOTADMINISTRATOR/$INSTALL_USER/g" /etc/security/rootasrole.json
chmod 0640 /etc/security/rootasrole.json || exit
if [ $DOCKER -eq 0 ]; then
	chattr +i /etc/security/rootasrole.json || exit
fi