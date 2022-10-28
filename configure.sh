#!/bin/bash

# Check that script is executed under sudo
if [ "$SUDO_USER" = "" ]; then
    echo "Please execute this script with sudo" >&2
    exit 1
fi;

echo "Capabilities & PAM packages installation"
apt-get install gcc llvm clang || exit
apt-get install libcap2 libcap2-bin libcap-dev libcap-ng-dev libelf-dev || exit
apt-get install libpam0g-dev || exit
apt-get install libxml2 libxml2-dev || exit

echo "Configuration files installation"
cp resources/sr_pam.conf /etc/pam.d/sr || exit
chmod 0644 /etc/pam.d/sr || exit
cp resources/capabilityRole.xml /etc/security || exit
echo "Define root role for the user $SUDO_USER:"
sed -i 's/ROOTADMINISTRATOR/'$SUDO_USER'/g' /etc/security/capabilityRole.xml
chmod 0644 /etc/security/capabilityRole.xml || exit
chattr +i /etc/security/capabilityRole.xml || exit

echo "configuration done. Ready to compile."
