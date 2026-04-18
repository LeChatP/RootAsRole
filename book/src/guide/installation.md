# Installation

For production-like setups, prefer distro packaging. Source install is useful for testing and development.

## Prerequisites

- Linux system with PAM
- Rust toolchain (if building from source)
- Administrative rights (`sudo` or equivalent)

## Build and install from source

```bash
git clone https://github.com/LeChatP/RootAsRole
cd RootAsRole
cargo xtask install -bip sudo
```

## What the installer does

`cargo xtask install -bip sudo` performs:

- dependency installation when required
- project build
- deployment of `dosr` and `chsr`
- capability/ownership setup for `dosr`
- installation of PAM config for `dosr`
- installation of `/etc/security/rootasrole.json`
- immutable flag setup on policy file when supported by the filesystem

> Warning: this installer runs with high administrative power. Review and tighten policy before multi-user deployment.