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

echo "Capabilities & PAM packages installation"

if [ ! `id -u` -eq 0 ]; then 
PRIV_EXE="${PRIV_EXE:-sudo}"
else
PRIV_EXE=""
fi

if command -v apt-get &>/dev/null; then
    $PRIV_EXE apt-get update
    $PRIV_EXE apt-get install "${YES}" "linux-headers-$(uname -r)" || $PRIV_EXE apt-get install "${YES}" linux-headers-generic
    $PRIV_EXE apt-get install "${YES}" linux-tools-common linux-tools-generic "linux-tools-$(uname -r)"
    $PRIV_EXE apt-get install "${YES}" man pkg-config openssl libssl-dev curl gcc llvm clang libcap2 libcap2-bin libcap-dev libcap-ng-dev libelf-dev libpam0g-dev libxml2 libxml2-dev libclang-dev make
    if [ -n "${DEBUG}" ]; then
        $PRIV_EXE apt-get install "${YES}" gdb
    fi;
    if [ -n "${COV}" ]; then
        $PRIV_EXE apt-get install "${YES}" gcovr
    fi;
elif command -v yum &>/dev/null; then
    $PRIV_EXE yum install ${YES} man pkgconfig openssl-devel curl gcc llvm clang clang-devel libcap libcap-ng elfutils libxml2 libxml2-devel make kernel-headers pam-devel bpftool    
    if [ -n "${DEBUG}" ]; then
        $PRIV_EXE yum install "${YES}" gdb
    fi;
    if [ -n "${COV}" ]; then
        $PRIV_EXE yum install "${YES}" gcovr
    fi;
elif command -v pacman &>/dev/null; then
    if [ -n "${YES}" ]; then
        NOCONFIRM="--noconfirm"
    fi
    $PRIV_EXE pacman -S "${NOCONFIRM}" man-db pkgconf openssl curl gcc llvm clang libcap libcap-ng libelf libxml2 linux-headers linux-api-headers make bpf
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

echo "Install Rust Cargo compiler"
if [ $(command -v cargo &>/dev/null; echo $?) -eq 0 ]; then 
	echo "Cargo is installed"
else
	curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly ${YES} # nightly because aya use -Z feature
fi

. "$HOME/.cargo/env"

# ask for user to install bpf-linker
cargo install --force bpf-linker bindgen-cli
cargo install --git https://github.com/aya-rs/aya -- aya-tool
aya-tool generate task_struct > capable-ebpf/src/vmlinux.rs

echo "dependencies installed. Ready to compile."
