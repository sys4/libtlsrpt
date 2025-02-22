All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2025-02-22 - first public release

### Fixed
- In tlsrpt_finish_delivery_request use correct final_result_t code TLSRPT_FINAL_FAILURE in case of an unfinished policy
- Changed internal debug functions to static
- Corrected typos in manpages

### Added
- datagram protocol version field "dpv" to generated datagrams
- manpages for new functions tlsrpt_version and tlsrpt_version_check
- function tlsrpt_version()
- API version test function tlsrpt_version_check
- new header file tlsrpt_version.h
- version information macros
- packaging/aur/PKGBUILD for Archlinux AUR package build source (#5)
