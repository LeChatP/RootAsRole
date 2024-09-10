#!/bin/sh
filesystem() {
    df -T "$1" | awk 'NR==2 {print $2}'
}

configure() {
    sed -i "s/ROOTADMINISTRATOR/$(id -urn)/g" /etc/security/rootasrole.json
    FS=$(filesystem /etc/security/rootasrole.json)
    case $FS in
    "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "ocfs2" | "jfs" | "reiserfs")
        chattr +i /etc/security/rootasrole.json
        ;;
    *)
        sed -i "s/\"CAP_LINUX_IMMUTABLE\"//g" /etc/security/rootasrole.json
        ;;
    esac
}

if [ -f /etc/security/rootasrole.json ]; then
    if grep -q "ROOTADMINISTRATOR" /etc/security/rootasrole.json; then
        configure
    fi
fi
