#!/bin/bash

CAP_DAC_OVERRIDE=1
CAP_LINUX_IMMUTABLE=9

has_capability() {
    local pid=$1
    local capability=$2

    # Read the CapEff line from the process's status file
    local cap_eff_hex
    cap_eff_hex=$(grep '^CapEff:' /proc/$pid/status | awk '{print $2}')
    if [[ -z "$cap_eff_hex" ]]; then
        echo "Could not read CapEff for process $pid"
        return 1
    fi

    # Convert the hex value to a decimal number
    local cap_eff_int
    cap_eff_int=$((16#$cap_eff_hex))

    # Check if the specific capability bit is set
    if ((cap_eff_int & (1 << capability))); then
        return 0
    else
        return 1
    fi
}

DOCKER=0
YES=""

while getopts "yd" opt; do
	case ${opt} in
		y ) YES="-y"
			;;
		d ) DOCKER=1
			;;
	esac
done

if [[ -z ${SUDO_USER+x} ]]; then INSTALL_USER=`id -urn`; else INSTALL_USER=$SUDO_USER; fi

if [[ $(has_capability "self" $CAP_DAC_OVERRIDE) == 0 ]] || ( [[ ${DOCKER} == 0 ]] && [[ $(has_capability "self" $CAP_LINUX_IMMUTABLE) == 0 ]] ); then
    echo "Vous avez besoin des capacités CAP_DAC_OVERRIDE et CAP_LINUX_IMMUTABLE pour exécuter ce script."
    exit 1
fi

export $(grep -h '^ID' /etc/*-release)

echo "Configuration files installation"
echo "id : ${ID}"
if [[ "${ID}" == "arch" ]]; then
    cp resources/arch_sr_pam.conf /etc/pam.d/sr || exit;
elif [[ "${ID}" == "ubuntu" ]] || [[ "${ID}" == "debian" ]]; then
    cp resources/deb_sr_pam.conf /etc/pam.d/sr || exit;
elif [[ "${ID}" == *"centos"* ]] || [[ "${ID}" == "fedora" ]] || [[ "${ID}" == *"rhel"* ]]; then
    cp resources/rh_sr_pam.conf /etc/pam.d/sr || exit;
else
    echo "Unable to find a supported distribution, exiting..."
    exit 3
fi


write() {
	if [[  ${DOCKER} -eq 0 ]] && [[ -e "/etc/security/rootasrole.json" ]]; then # Docker does not support immutable
		chattr -i /etc/security/rootasrole.json
	fi
	cp resources/rootasrole.json /etc/security || exit
	echo "Define root role for the user $INSTALL_USER"
	sed -i "s/ROOTADMINISTRATOR/$INSTALL_USER/g" /etc/security/rootasrole.json
	if [[  ${DOCKER} -eq 1 ]]; then
		sed -i "s/\"immutable\": true/\"immutable\": false/g" /etc/security/rootasrole.json
		sed -i "s;\"CAP_LINUX_IMMUTABLE\";;g" /etc/security/rootasrole.json
	fi
}

if [[ $INSTALL_USER == "0" ]]; then
	echo "Warning: You run this script as real root, so the administrator role is defined for the root user"
fi

if [[ ! -e "/etc/security/rootasrole.json" ]] || [[  "${YES}" = "-y" ]]; then
	write
else
	read -r -p "Reconfigure policy? [y/N] " response
	case "$response" in
		[yY][eE][sS]|[yY]) 
			write
			;;
	esac
fi

chmod 0644 /etc/pam.d/sr || exit
chmod 0640 /etc/security/rootasrole.json || exit
if [[  $DOCKER -eq 0 ]]; then
	chattr +i /etc/security/rootasrole.json || exit
fi

echo "Configuration done, Ready to compile."
