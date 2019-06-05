# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

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

[Unreleased]: https://github.com/SamerW/RootAsRole/compare/V1.0...HEAD
[2.0]: https://github.com/SamerW/RootAsRole/compare/V1.1...V2.0
[1.1]: https://github.com/SamerW/RootAsRole/compare/V1.0...V1.1
[1.0]: https://github.com/SamerW/RootAsRole/releases/tag/V1.0
