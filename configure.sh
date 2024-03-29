#!/bin/bash

if [ -e "/etc/security/rootasrole.kdl" ];then
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