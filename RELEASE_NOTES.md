# libtlsrpt 0.5.1

Released: 2026-08-31

## Highlights

The 0.5.1 release of libtlsrpt clarifies that libtlsrpt is released under [GNU Lesser General Public License (LGPL)](COPYING).
Some left-over files from the early development stages when libtlsrpt was in the same project with tlsrpt-reporter might have caused confusion.

## Changes
See [CHANGELOG.md](./CHANGELOG.md).

## Upgrade notes

Apart from the changed version number in the version information functions, no changes to the actual library code happened.

We now provide a pkg-config file.

The build process for the manual pages was changed to use GNU Autotools along with the library.
Therefore a new build-time dependency to ascii-doctor was introduced, but only when building from the checked-out source code.
The created manpage artifacts are shipped in the .tar.gz file created by `make dist`.

## Artifacts

- `libtlsrpt-0.5.1.tar.gz`     — source distribution
- `libtlsrpt-0.5.1.tar.gz.asc` — detached PGP signature
- `SHA256SUMS`                 — checksums of all artifacts

## Verification
```sh
gpg --verify libtlsrpt-0.5.1.tar.gz.asc libtlsrpt-0.5.1.tar.gz
sha256sum -c SHA256SUMS
```

