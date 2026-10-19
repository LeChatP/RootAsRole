# Installation

## Compatibility

The Linux capabilities feature is available in kernel >= 4.3. So dosr tool is compatible with at least this version.

The eBPF compilation minimal features are available in kernel >= 5.0, so capable, gensr tools are compatible with at least this version.


## Install from Linux distributions

**We really need your help to bring the project to Linux distributions repositories! Please contribute 🙏!**


### Arch Linux (AUR)

```sh
git clone https://aur.archlinux.org/dosr.git
cd dosr
makepkg -si
```
you can also use `yay` AUR manager or any other one you like. Please __**vote**__ for the [AUR](https://aur.archlinux.org/packages/dosr) if you want it into pacman `extra` repo! All you need is an [Arch AUR account](https://aur.archlinux.org/login) and you could vote for the AUR 🙂


## Compile and install from source

This is a complete process for compiling and installing `dosr` and `chsr` binaries.

### Prerequisites

- Linux system with PAM
- Rust toolchain
- Administrative rights (`sudo` or equivalent)

### Retrieve the source code

```bash
git clone https://github.com/LeChatP/RootAsRole
cd RootAsRole
```

## Dependencies installation, compiling and installing

Before installing the tool, you might want to define some default behaviors. You'll find them in this page [Build-time default configuration](build.md).

It might be trivial, but in order to install RootAsRole, you needs full administrative privileges. But only for specific cases when needed. Again, even here, we wants to apply PoLP. However, compiling a program will never need privileges. So managing unprivileged compilation and privileged installation is a bit tricky.

To manage that, we developed an installation helper tool

```bash
cargo xtask install -bip sudo
```

This command performs:

- dependency installation when required (privileged)
- project build
- deployment of `dosr` and `chsr` in `RAR_BIN_PATH` (privileged)
- capability/ownership setup for `dosr` (privileged)
- installation of PAM config for `dosr` with `RAR_PAM_SERVICE` name (privileged)
- installation of the configuration and policy with `RAR_CFG_PATH` and `RAR_CFG_DATA_PATH` paths (privileged)
- immutable flag setup on policy file when supported by the filesystem controlled with `RAR_CFG_IMMUTABLE` (privileged)

<blockquote class="caroot">
If you don't have sudo installed, you can use su, doas or please binaries. They should work as expected.
</blockquote>