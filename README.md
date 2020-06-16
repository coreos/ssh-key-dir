# ssh-key-dir

[![Build status](https://travis-ci.org/coreos/ssh-key-dir.svg?branch=master)](https://travis-ci.org/coreos/ssh-key-dir)
[![crates.io](https://img.shields.io/crates/v/ssh-key-dir.svg)](https://crates.io/crates/ssh-key-dir)

ssh-key-dir is an sshd [`AuthorizedKeysCommand`](https://man.openbsd.org/sshd_config#AuthorizedKeysCommand) that reads SSH authorized key files from a directory, `~/.ssh/authorized_keys.d`.  It allows SSH keys to be managed by multiple tools and processes, without competing over `~/.ssh/authorized_keys`.

ssh-key-dir reads key files in lexigraphical order, ignoring any filenames starting with a dot.

# Installing

## Installing on Fedora

`ssh-key-dir` is packaged in Fedora:

```sh
sudo dnf install ssh-key-dir
```

Installing the package automatically configures sshd to read keys using ssh-key-dir.

## Installing with Cargo

You can also install just the `ssh-key-dir` binary with Rust's Cargo package manager:

```sh
cargo install ssh-key-dir
```

## Build and install from source tree

To build from the source tree:

```sh
make
```

To install the binary and `sshd_config.d` fragment to a target rootfs (e.g. under a [coreos-assembler](https://github.com/coreos/coreos-assembler) workdir):

```sh
make install DESTDIR=/my/dest/dir
```
