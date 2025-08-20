## Installation

### Prerequisites

Install git

### How to build

  1. git clone <https://github.com/LeChatP/RootAsRole>
  1. cd RootAsRole
  1. cargo xtask install -bip sudo

<div class="warning">
<b>
The installation process requires CAP_SETFCAP privileges and also grants full privileges to the user who installs, making them privileged by default.</b>

</div>

### What does the installation script do?

The installation script parameters explaination:
- cargo xtask install -bip sudo
  - (-b) Builds the project
  - (-i) Installs necessary dependencies
  - (-p) Use the `sudo` command to perform administrative tasks

Install script does the following:
- Dependency Step :
  - Installing necessary dependencies considering if compiling from source.
- Build Step :
  - Building sr and chsr binaries
- Install Step : 
  - Copying sr and chsr binaries to /usr/bin
  - Setting all capabilities on /usr/bin/sr
  - Setting owners and permissions on /usr/bin/sr
- Configuration Step :
  - Deploying /etc/pam.d/sr for PAM configuration
  - Deploying /etc/security/rootasrole.json for configuration
  - Setting immutable on /etc/security/rootasrole.json if filesytem supports it