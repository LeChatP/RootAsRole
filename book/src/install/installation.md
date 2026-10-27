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

## Dependencies installation

Since 4.2.0, we removed the auto dependencies installation through `cargo xtask` because it takes responsibilities that are not the purpose of the project. So we now require you to install dependencies yourself: 

| Distribution | Dependencies |
|---|---|
| Debian, Ubuntu | `apt install clang pkg-config libpam0g-dev libseccomp-dev pandoc` |
| Fedora, RHEL family | `dnf install clang pkgconfig pam-devel libseccomp-devel pandoc` |
| openSUSE | `zypper install clang pkg-config pam-devel libseccomp-devel pandoc` |
| Arch Linux | `pacman -S clang pkgconf pam libseccomp pandoc-cli` |

Note that `clang` is selected in the case you want to compile the capable tool. If you prefer using `gcc`, feel free to use it instead.

Also, `pandoc` is only required if you want to build the man pages from source.

If you are using another distribution, you can find their names on these websites [pkgs.org](https://pkgs.org/) or [repology.org](https://repology.org/).

If you miss any dependency, you can use the `cargo xtask doctor` command.

### Retrieve the source code

```bash
git clone https://github.com/LeChatP/RootAsRole
cd RootAsRole
```

## Compiling and installing

Before installing the tool, you might want to define some default behaviors. You'll find them in this page [Build-time default configuration](build.md).

It might be trivial, but in order to install RootAsRole, you needs full administrative privileges. But only for specific cases when needed. Again, even here, we wants to apply PoLP. However, compiling a program will never need privileges. So managing unprivileged compilation and privileged installation is a bit tricky.

To manage that, we developed an installation helper tool

```bash
cargo xtask install -bp sudo
```

This command performs:

- project build
- deployment of `dosr` and `chsr` in `RAR_BIN_PATH` (privileged)
- capability/ownership setup for `dosr` (privileged)
- installation of PAM config for `dosr` with `RAR_PAM_SERVICE` name (privileged)
- installation of the configuration and policy with `RAR_CFG_PATH` and `RAR_CFG_DATA_PATH` paths (privileged)
- immutable flag setup on policy file when supported by the filesystem controlled with `RAR_CFG_IMMUTABLE` (privileged)

<blockquote class="caroot">
If you don't have sudo installed, you can use su, doas or please binaries. They should work as expected.
</blockquote>