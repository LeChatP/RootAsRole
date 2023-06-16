# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [3.0] - 2022-12-04

### Role Design

In this Major version, conception of sr tool is redesigned. ancient versions of RootAsRole doesn't respect properly the RBAC model, or in other point of view, didn't respect least privilege principle. Privileges should be associated directly to command(s), not to a role, because a role is a set of permissions that needs different privileges. As example, considering that network administrator needs to access to CAP_NET_BIND_SERVICE to setup his network monitoring service, he doesn't need to edit network interfaces configuration with CAP_NET_ADMIN. So the role needs a first command which has CAP_NET_BIND_SERVICE to start monitoring service and a second command with CAP_NET_ADMIN for edit network configuration. In previous implementation, this configuration should need 2 different roles, which is not the meaning of RBAC model.

In this new version, we focuses on usability and conception of the tool. Because sudo is simpler to use, we redesigned `sr` argument management, which is now minimal, for the happiness of lazy people. RootAsRole is now a more lazy tool than `sudo` because our tool needs only 2 characters, which means 2 times less than `sudo`. We know that `sudo` is used in majority of distributions, so to avoid to change habits, we tried to reproduce the default usage of this tool. We know that sudo provides more functionnalities than our tool. But we think that sudo tries to resolve overloaded amount of needs which became very hard to modify without incidents.

As reminder, `sudo` doesn't respect any security model https://security.stackexchange.com/a/67218. With `sr` we tried to setup a Role based access control model which allows administrator to manage privileges granting in respect of least privilege management. We also know that capabilities tries to respect capability based security model by using similar words. But the design is not respecting this model. Contrary to `sudo`, RootAsRole doesn't permit to user to change his effective identity.

Also, With this new version, many vulnerabilities were fixed.

### Role-Management

Role-management is entierly redesigned. Rust is coming into Linux Kernel ! To approve this initiative, we decided to learn this language and try to implement it as best we could do on this days. Don't be rough, we are beginners on this language. Also, Rust fullfill security needs for the project. That's why Rust will be encouraged in the future.
We thought that previous cli were not that easy to use. So we thought about a TUI to structure and design our tool. Yes, a cli version is still available. By doing this TUI, we learnt a lot about Rust language mechanisms. That could help us to create a better cli.

### eBPF

`capable` is now working on Debian ! Because Debian is using a different implementation structure of headers, we had difficulties to handle Ubuntu, Debian and other OS.
In next versions, we'll enhance eBPF with new ways of implementation and some exciting functionnalities!

With these changes, RootAsRole, has taken initiatives to simplify the deployment of least privilege principle based on process criteria.



## Added

 - Evironment Variables management
 - Support for Arch Linux
 - setUID and Multiple setGID
 - Partial Order Comparison between roles ! Ghosted roles abolished !
 - Unit-Test with [Criterion Testing Framework](https://github.com/Snaipe/Criterion)

## Changed 

 - XML Document DTD and conceptual structure


## Deleted

 - `sr_aux` program which was useless.
 - old `role-manager` implementation. It wasn't working at all, and source code wasn't reusable.

## [2.2] - 2019-09-27

This version is focused on sr command, no changes in capable command

### Added

- Improve "-i" option, as user-friendly as possible. Explain every possibilities to specific user. If you don't know if you can, then do "-i"

### Modified

- fix quotes and apostrophes in sr
- fix various bugs with unwanted strings
- Some Refactoring and optimisations

## [2.1] - 2019-08-14

This version is focused on capable program, no changes on sr command.

### Added

- New algorithm capabilities detection for capable command, based on namespaces with recursive namespace creation detection. This algorithm will work for almost all cases and is much more optimized than 2.0 algorithm.
- Beginning of stack trace filtering for capable command, we want to remove the cap_sys_admin capability when _do_fork is in the stack will work only on kernel version 5.X, the program remains retro-compatible for 4.10 version

### Modified

- 2.0 algorithm has now the namespace retrieving
- fix big mistakes on 2.0 algorithm
- fix output options management
- fix hidden memory leaks on capable tool

### Removed

- raw option removed for production usage, because the raw log is stored on desktop until shutdown can slow down the system when used in long time, furthermore the raw option isn't pertinent.

## [2.0] - 2019-06-04

### Added

- New Tool called "capable". this tool can be used to resolve capabilities asked by a program, this can be run as daemon, or with command to test.
- sr is now print which role is used when start

### Changed

- option -c is optionnal but it's mandatory to precise the command in the configuration.
- Fix bugs and memory leaks from testing suite and sr

## [1.1] - 2019-05-02

### Added

- Ability to no longer specify a role for the command sr
- Adding tests for functionality without role
- Added a system test environment
- README for testing system
- Adding tests for the test environment
- Added optional parameter -v to get the RAR version
- Added Changelog file

### Changed

- Correction of syntactical faults in the main README
- Fixed DTD on capabilities (require at least one capability in a role)

## [1.0] - 2018-07-28

### Added

- sr command which uses capabilities and xml role system to replace `sudo` or any alternative.
- initial project

[Unreleased]: https://github.com/SamerW/RootAsRole/compare/V2.2...HEAD
[2.2]: https://github.com/SamerW/RootAsRole/compare/V2.1...V2.2
[2.1]: https://github.com/SamerW/RootAsRole/compare/V2.0...V2.1
[2.0]: https://github.com/SamerW/RootAsRole/compare/V1.1...V2.0
[1.1]: https://github.com/SamerW/RootAsRole/compare/V1.0...V1.1
[1.0]: https://github.com/SamerW/RootAsRole/releases/tag/V1.0
