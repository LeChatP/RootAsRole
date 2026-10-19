#!/bin/bash
# Build and install the copied tree in the virtual machine, as root (see the Vagrantfile).
set -euo pipefail

. /etc/os-release
case "$ID" in
    debian | ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y build-essential curl git pkg-config e2fsprogs libcap2-bin python3
        ;;
    arch)
        pacman -Syu --noconfirm --needed base-devel curl git e2fsprogs libcap python
        ;;
    *)
        echo "provision.sh: unsupported distribution $ID" >&2
        exit 1
        ;;
esac

# the build needs a recent Rust, the one of the distribution may be too old
sudo -u vagrant -i bash -c '
    command -v "$HOME/.cargo/bin/cargo" >/dev/null ||
        curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
'
# the other dependencies come from xtask (-i), sudo is the privilege escalation it uses (-p)
sudo -u vagrant -i bash -c '
    . "$HOME/.cargo/env"
    cd "$HOME/RootAsRole"
    cargo xtask install -bip sudo
'
