# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] - 2025-04-29

### Added

- Log validation error details in salt log

## [1.3.0] - 2024-10-10

### Added

- Allow disabling directory creation
- Support configuring a domain name as the nameserver address

## [1.2.0] - 2021-02-15

### Added

- Support for `dnspython` 2.0, Salt 3002, Python 3.9
- Allow customizing file path for private key and certificate files

## [1.1.0] - 2020-08-04

### Added

- Check DNS propagation to nameservers
- Option to configure account directory

## [1.0.1] - 2020-07-16

### Fixed

- Catch missing `dnspython` in `acme_dns`

## 1.0.0 - 2020-07-13

### Added

- First release with basic feature set

[Unreleased]: https://github.com/jgraichen/salt-acme/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/jgraichen/salt-acme/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/jgraichen/salt-acme/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/jgraichen/salt-acme/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/jgraichen/salt-acme/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/jgraichen/salt-acme/compare/v1.0.0...v1.0.1
