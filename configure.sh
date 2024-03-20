#!/bin/bash

# Check that script is executed under sudo
if [ -z "${SUDO_USER}" ]; then
    echo "Please execute this script with sudo" >&2
    exit 1
fi;

DOCKER=0

while getopts "yd" opt; do
    case ${opt} in
        y ) YES="-y"
        ;;
        d ) DOCKER=1
        ;;
        * ) ;;
    esac
done

echo "Capabilities & PAM packages installation"
if command -v apt-get &>/dev/null; then
    apt-get install "${YES}" pkg-config openssl libssl-dev curl gcc llvm clang libcap2 libcap2-bin libcap-dev libcap-ng-dev libelf-dev libpam0g-dev libxml2 libxml2-dev libclang-dev make "linux-headers-$(uname -r)"
    if [ -n "${DEBUG}" ]; then
        apt-get install "${YES}" gdb
    fi;
    if [ -n "${COV}" ]; then
        apt-get install "${YES}" gcovr
    fi;
    elif command -v yum &>/dev/null; then
    yum install "${YES}" pkgconfig openssl-devel curl gcc llvm clang clang-devel libcap libcap-ng libelf libxml2 libxml2-devel make kernel-headers pam-devel
    if [ -n "${DEBUG}" ]; then
        yum install "${YES}" gdb
    fi;
    if [ -n "${COV}" ]; then
        yum install "${YES}" gcovr
    fi;
    elif command -v pacman &>/dev/null; then
    pacman -S "${YES}" pkgconf openssl curl cargo-make gcc llvm clang libcap libcap-ng libelf libxml2 linux-headers linux-api-headers make
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

echo "Install Rust Cargo compiler"
if [ "$(which cargo &>/dev/null ; echo $?)" -eq "0" ]; then
    echo "Cargo is installed"
else
    curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly ${YES}
fi

if [ ! -f "/usr/bin/cargo" ]; then
    mv -f ~/.cargo/bin/cargo /usr/local/bin
    ln -s /usr/local/bin/cargo /bin/cargo
    echo "$HOME/.cargo/bin/cargo program is copied to /usr/local/bin"
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

if [ -e "/etc/security/rootasrole.xml" ];then
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


echo "configuration done. Ready to compile."