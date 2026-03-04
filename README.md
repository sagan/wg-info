# wg-info (Rust version)

This is the Rust port of [wg-info](https://codeberg.org/aylen384/wg-info) Python script,
which displays wireguard status with each peer's name. For your convenience,
this port version also displays the wg interface's self ip by parsing `ip addr show dev wg0` output.

Written by Gemini 3.1 Pro.

## Usage

```
# ./wg-info -h
Wireguard Info
==============

This tool enhances the output of 'wg show' to include node names.
Also it can ping the nodes (using the first ip in AllowedIPs)
and indicate the online status via red/green color coding.

It expects you to use wg-quick and reads the wg-quick config at
/etc/wireguard/INTERFACE.conf

The human readable peer names are expected in the wg-quick config 
within a comment like this:
[Peer]
# Name = Very secret node in antarctica

Usage: wg-info [OPTIONS]

Options:
      --html                   Format output as HTML
      --tty                    Force terminal colors even when writing to pipe
  -p, --ping                   Ping all nodes (in parallel) and show online status
  -i, --interface <INTERFACE>  Only show status for this interface
  -f, --filter <FILTER>        Filter peers by name or allowed ips
  -h, --help                   Print help
  -V, --version                Print version
```

## Build

Install Rust. Then install [cross](https://crates.io/crates/cross): `cargo install cross`. Note `cross` uses Docker.

Build Linux amd64:

```
cross build --target x86_64-unknown-linux-musl --release
```

Build Linux arm64:

```
cross build --target aarch64-unknown-linux-musl --release
```

Build Linux mipsle (soft float):

```
cross +nightly build --target mipsel-unknown-linux-musl \
  -Z build-std=std,core,alloc,panic_unwind \
  --release
```

The built binary can be found in `target/x86_64-unknown-linux-musl/release` dir.
