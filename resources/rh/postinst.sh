if [[ -z ${SUDO_USER+x} ]]; then INSTALL_USER=`id -urn`; else INSTALL_USER=$SUDO_USER; fi

filesystem() {
    df -T "$1" | awk 'NR==2 {print $2}'
}

configure() {
    echo "Configuring rootasrole.json"
	sed -i "s/ROOTADMINISTRATOR/$INSTALL_USER/g" /etc/security/rootasrole.json
    FS=$(filesystem /etc/security/rootasrole.json)
    case $FS in
    "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "ocfs2" | "jfs" | "reiserfs")
        echo "Setting immutable attribute on /etc/security/rootasrole.json"
        chattr +i /etc/security/rootasrole.json
        ;;
    *)
        echo "filesystem $FS does not support immutable attribute"
        echo "Removing immutable parameter from /etc/security/rootasrole.json"
		sed -i "s/\"immutable\": true/\"immutable\": false/g" /etc/security/rootasrole.json
		sed -i "s;\"CAP_LINUX_IMMUTABLE\";;g" /etc/security/rootasrole.json
        ;;
    esac
}

if [ -f /etc/security/rootasrole.json ]; then
    if grep -q "ROOTADMINISTRATOR" /etc/security/rootasrole.json; then
        configure
    fi
fi
