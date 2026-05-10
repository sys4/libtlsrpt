All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1-rc1] - 2026-05-10

### Fixed
- Clarified license information: libtlsrpt is LGPLv3, removed stale references to GPLv3

### Changed
- the manpages created from .adoc files are no longer in the git repository, but are still shipped in the tar-balls
- the library C-code had no changes except for the version information

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
