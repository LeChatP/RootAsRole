# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

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
