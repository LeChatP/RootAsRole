#!/bin/bash
# Build and install the copied tree in the virtual machine, as root (see the Vagrantfile).
# xtask checks the packages to build RootAsRole and does not install them: they come from here.
set -euo pipefail

. /etc/os-release
case "$ID" in
    debian | ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y build-essential curl git pkg-config e2fsprogs libcap2-bin python3 \
            clang libpam0g-dev libseccomp-dev pandoc
        ;;
    arch)
        pacman -Syu --noconfirm --needed base-devel curl git e2fsprogs libcap python \
            clang pam libseccomp pandoc-cli
        ;;
    *)
        echo "provision.sh: unsupported distribution $ID" >&2
        exit 1
        ;;
esac

# The scripts run as vagrant with -H, not -i: sudo -i escapes the newlines of a command, which
# the login shell then joins as line continuations, so only the first line ran.
# the build needs a recent Rust, the one of the distribution may be too old
sudo -u vagrant -H bash -c '
    set -euo pipefail
    command -v "$HOME/.cargo/bin/cargo" >/dev/null ||
        curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
'
# sudo is the privilege escalation that xtask uses (-p)
sudo -u vagrant -H bash -c '
    set -euo pipefail
    . "$HOME/.cargo/env"
    cd "$HOME/RootAsRole"
    cargo xtask install -bp sudo
'
