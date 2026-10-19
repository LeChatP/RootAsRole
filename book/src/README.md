# The RootAsRole project

*by Eddie Billoir*

This is the documentation for the RootAsRole project, including dosr, chsr, capable, and gensr, assuming that you want to use the latest version of the project.
If you are looking for older versions, please refer to the github history of the project.

## Features

* [A structured access control model based on Roles](https://dl.acm.org/doi/10.1145/501978.501980)
  * [Role hierarchy](https://dl.acm.org/doi/10.1145/501978.501980)
  * [Static/Dynamic Separation of Duties](https://dl.acm.org/doi/10.1145/501978.501980)
* [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) support
* [Highly configurable](configuration.md)
* Command matching with [glob](https://docs.rs/glob/latest/glob/) for binary path and [PCRE2](https://www.pcre.org/) for command arguments
* 🛠️ Configuration Helpers:
   * [capable](https://github.com/LeChatP/RootAsRole-capable): Analyze command rights
   * [gensr](https://github.com/LeChatP/RootAsRole-gensr): Generate policy from Ansible playbooks

## Mascott

In this book, you'll find CaRoot, our mascott! It'll give advices all along you read the documentation.