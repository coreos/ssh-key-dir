# Release notes

## Upcoming ssh-key-dir 0.1.5 (unreleased)

Changes:

- Replace deprecated dependency users by uzers
- Cargo.toml: bump MSRV to 1.75.0


## ssh-key-dir 0.1.4 (2022-09-27)

Changes:

-  Require Rust ≥ 1.58
-  Require clap ≥ 3.1
-  Remove Windows binaries from vendor archive


## ssh-key-dir 0.1.3 (2022-01-18)

Changes:

- Switch error handling from error-chain to anyhow
- Update clap to 3.0


## ssh-key-dir 0.1.2 (2020-06-26)

Changes:

- Skip FIFOs rather than blocking indefinitely


## ssh-key-dir 0.1.1 (2020-06-16)

Changes:

- Fix ownership check when running as root for non-root user


## ssh-key-dir 0.1.0 (2020-06-16)

Changes:

- Initial release
