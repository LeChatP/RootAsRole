#/bin/sh

# This script build every package for Arch Linux, Debian, Fedora.

cargo build --release --bin sr --bin chsr || exit 1

# Arch Linux
if [ -z "$ARCH" ]; then
    ARCH=$(uname -m)
fi
PKGEXT=.pkg.tar.zst


mkdir -p target/arch/usr/bin
mkdir -p target/arch/etc/pam.d
mkdir -p target/arch/usr/share/rootasrole
cp target/release/sr target/release/chsr target/arch/usr/bin
cp resources/rootasrole.json target/arch/usr/share/rootasrole/default.json
cp resources/arch/arch_sr_pam.conf target/arch/etc/pam.d/sr
cp resources/arch/PKGBUILD resources/arch/rootasrole.install target/arch

sed -i "s/%ARCH%/$ARCH/g" target/arch/PKGBUILD

cd target/arch

makepkg -f -p PKGBUILD
