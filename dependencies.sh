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

if [ ! `id -u` -eq 0 ]; then 
	echo "You need to run this script as root"
    exit 1
fi

echo "Install Rust Cargo compiler"
if [ $(whereis cargo &>/dev/null ; echo $?) -eq 0 ] && [ -f "/bin/cargo" ]; then 
	echo "Cargo is installed"
elif [ "${YES}" == "-y" ]; then
	curl https://sh.rustup.rs -sSf | sh -s -- -y
else
	curl https://sh.rustup.rs -sSf | sh
fi

if [ ! -f "/bin/cargo" ]; then
	cp ~/.cargo/bin/cargo /usr/bin
    ln -s /usr/bin/cargo /bin/cargo
	echo "as $HOME/.cargo/bin/cargo cargo program is copied to /usr/bin"
fi

echo "Capabilities & PAM packages installation"
if command -v apt-get &>/dev/null; then
    apt-get update "${YES}"
    apt-get install "${YES}" "linux-headers-$(uname -r)" || apt-get install "${YES}" linux-headers-generic
    apt-get install "${YES}" man pkg-config openssl libssl-dev curl gcc llvm clang libcap2 libcap2-bin libcap-dev libcap-ng-dev libelf-dev libpam0g-dev libxml2 libxml2-dev libclang-dev make
    if [ -n "${DEBUG}" ]; then
        apt-get install "${YES}" gdb
    fi;
    if [ -n "${COV}" ]; then
        apt-get install "${YES}" gcovr
    fi;
elif command -v yum &>/dev/null; then
    yum install "${YES}" man pkgconfig openssl-devel curl gcc llvm clang clang-devel libcap libcap-ng libelf libxml2 libxml2-devel make kernel-headers pam-devel
    if [ -n "${DEBUG}" ]; then
        yum install "${YES}" gdb
    fi;
    if [ -n "${COV}" ]; then
        yum install "${YES}" gcovr
    fi;
elif command -v pacman &>/dev/null; then
    pacman -S "${YES}" man pkgconf openssl curl cargo-make gcc llvm clang libcap libcap-ng libelf libxml2 linux-headers linux-api-headers make
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

# ask for user to install bpf-linker
if [ "${YES}" == "-y" ]; then
    echo "cargo install bpf-linker into /usr/local/bin"
    cargo install --force bpf-linker
    mv -f ~/.cargo/bin/bpf-linker /usr/local/bin
    ln -s /usr/local/bin/bpf-linker /bin/bpf-linker
else
    read -r -p "Install bpf-linker in /usr/local/bin? (mandatory for build) [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]|[oO])
            echo "cargo install bpf-linker into /usr/local/bin"
            cargo install --force bpf-linker
            mv -f ~/.cargo/bin/bpf-linker /usr/local/bin
            ln -s /usr/local/bin/bpf-linker /bin/bpf-linker
        ;;
    esac
fi

echo "dependencies installed. Ready to compile."
