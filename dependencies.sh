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

echo "Install Rust Cargo compiler"
if [ $(cargo &>/dev/null ; echo $?) -eq 0 ]; then 
	echo "Cargo is installed"
else
	curl https://sh.rustup.rs -sSf | sh -s -- ${YES}
fi

. "$HOME/.cargo/env"

echo "Capabilities & PAM packages installation"

if [ ! `id -u` -eq 0 ]; then 
PRIV_EXE="${PRIV_EXE:-sudo}"
else
PRIV_EXE=""
fi

if command -v apt-get &>/dev/null; then
    $PRIV_EXE apt-get update "${YES}"
    $PRIV_EXE apt-get install "${YES}" "linux-headers-$(uname -r)" || $PRIV_EXE apt-get install "${YES}" linux-headers-generic
    $PRIV_EXE apt-get install "${YES}" man pkg-config openssl libssl-dev curl gcc llvm clang libcap2 libcap2-bin libcap-dev libcap-ng-dev libelf-dev libpam0g-dev libxml2 libxml2-dev libclang-dev make
    if [ -n "${DEBUG}" ]; then
        $PRIV_EXE apt-get install "${YES}" gdb
    fi;
    if [ -n "${COV}" ]; then
        $PRIV_EXE apt-get install "${YES}" gcovr
    fi;
elif command -v yum &>/dev/null; then
    $PRIV_EXE yum install "${YES}" man pkgconfig openssl-devel curl gcc llvm clang clang-devel libcap libcap-ng libelf libxml2 libxml2-devel make kernel-headers pam-devel
    if [ -n "${DEBUG}" ]; then
        $PRIV_EXE yum install "${YES}" gdb
    fi;
    if [ -n "${COV}" ]; then
        $PRIV_EXE yum install "${YES}" gcovr
    fi;
elif command -v pacman &>/dev/null; then
    $PRIV_EXE pacman -S "${YES}" man pkgconf openssl curl cargo-make gcc llvm clang libcap libcap-ng libelf libxml2 linux-headers linux-api-headers make
    if [ -n "${DEBUG}" ]; then
        $PRIV_EXE pacman -S "${YES}" gdb
    fi;
    if [ -n "${COV}" ]; then
        $PRIV_EXE pacman -S "${YES}" gcovr
    fi;
else
    echo "Unable to find a supported package manager, exiting..."
    exit 2
fi

# ask for user to install bpf-linker
if [ "${YES}" == "-y" ]; then
    echo "cargo install bpf-linker into /usr/local/bin"
    cargo install --force bpf-linker
else
    read -r -p "Install bpf-linker in /usr/local/bin? (mandatory for build) [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]|[oO])
            echo "cargo install bpf-linker into /usr/local/bin"
            cargo install --force bpf-linker
        ;;
    esac
fi

echo "dependencies installed. Ready to compile."
