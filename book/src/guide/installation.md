## Installation

### Prerequisites

Install git

### How to build

  1. git clone <https://github.com/LeChatP/RootAsRole>
  1. cd RootAsRole
  1. sudo ./dependencies.sh
  1. sudo ./configure.sh
  1. sudo make install

<div class="warning">
<b>
The installation process requires CAP_SETFCAP privileges and also grants full privileges to the user who installs, making them privileged by default.</b>

</div>

### What does the installation script do?

The installation script does the following:
- dependencies.sh
  - Installs Rust and Cargo
  - Copy cargo binary to /usr/local/bin directory
  - Create a link /usr/local/bin/cargo to /bin/cargo
  - Installs `pkgconf openssl curl cargo-make gcc llvm clang libcap libcap-ng libelf libxml2 linux-headers linux-api-headers make`
  - Installs `bpf-linker` tool for `capable` eBPF tool
- configure.sh
  - Deploy `sr` PAM module to /etc/pam.d directory
  - Deploy `rootasrole.json` to /etc/security directory
  - Set immutable attribute to `rootasrole.json` file. Note : It requires a compatible filesystem like ext2/3/4, xfs, btrfs, reisefs, etc. 
  - Define the user who installs the project in a role which has all capabilities for all commands.
- Executes make install  
  - Compiles `sr`, `chsr` and `capable` binaries
  - Deploy `sr`, `chsr` and `capable` binaries to /usr/bin directory
  - Set user and group ownership of `sr`, `chsr` and `capable` binaries to root
  - Set file access permissions of `sr`, `chsr` and `capable` binaries to `r-xr-xr-x`
  - Set file capabilities of `sr`, `chsr` and `capable` binaries