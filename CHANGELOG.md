# Registration Server Changelog

## [Unreleased]

## [0.3.0] - 2020-09-13
### Changed
- Now using 2018 edition of Rust.
- Invalid POST requests to action resources now generate an error status.
- Switched framework from iron to actix-web.
### Added
- Ability to included arbitrary numbers of CAA, MX, and TXT records.
- Ability to point www/bare domain to a separate address.
### Fixed
- DNS responses now only include the appropriate records.

[Unreleased]: https://github.com/mozilla-iot/registration_server/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/mozilla-iot/registration_server/compare/v0.2.0...v0.3.0
