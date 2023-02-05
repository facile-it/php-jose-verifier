# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased] - yyyy-mm-dd

Here we write upgrading notes for brands. It's a team effort to make them as
straightforward as possible.

### Added
- Add support for PHP 8.2

### Changed
- Drop support for PHP 7.2
- Drop support for PHP 7.3
- Changed [`psalm`](https://psalm.dev) types
- Changed builders to be immutable
- Moved builders in `Facile\JoseVerifier\Builder` namespace

### Fixed
- Fixed check for mandatory `auth_time` when `require_auth_time` is `true`

### Removed
- Removed [`psalm`](https://psalm.dev) plugin
