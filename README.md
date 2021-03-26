# cuid-rust

[![Travis Build Status](https://travis-ci.com/mplanchard/cuid-rust.svg?branch=master "Master Status")](https://travis-ci.com/mplanchard/cuid-rust)
[![Crates.io](https://img.shields.io/crates/v/cuid "Crates.io")](https://crates.io/crates/cuid/)
[![docs.rs](https://docs.rs/cuid/badge.svg)](https://docs.rs/cuid/badge.svg)

Cuids are "Collision-resistant ids optimized for horizontal scaling and
binary search lookup performance."

This is a rust implementation of the CUID library, the original JavaScript
implementation of which may be found [here](https://github.com/ericelliott/cuid)

## Installation

In cargo.toml

```toml
cuid = "1.0.1"
```

## Usage

```rust
use cuid;

fn main() -> () {
    println!("{}", cuid::cuid().unwrap());
    println!("{}", cuid::slug().unwrap());
}
```

This package also provides a binary:

```sh
> cargo run cuid
cq64d5t05g4lx7twdb3t
```

## Performance

Performance is one of the primary concerns of this library (see
[Benchmarking](#benchmarking), below).

Currently, it takes about 405 nanoseconds to generate a CUID, or 335 nanoseconds
to generate a CUID slug, on modern desktop hardware.

In a long-running process or thread, CUID generation is faster, since the system
fingerprint is calculated once and then re-used for the lifetime of the process.
In this case, CUID generation takes about 125 ns.

## Tests

Tests can be run with

```text
cargo test
```

Note that some tests require tests run in a single thread. These are ignored by
default. They can be run with:

```text
cargo test -- --ignored --test-threads=1
```

## Benchmarking

Inline benchmarks are available when running with the nightly toolchain. There
are also criterion bnechmarks in [`benches/cuid.rs`][benches].

If you're on a Linux system, it's recommended to run benchmarks with the
maximum possible priority, via `nice`, in order to avoid confounding effects
from other processes running on the system:

```text
$ nice -n -20 cargo bench
```

[benches]: ./benches/cuid.rs
