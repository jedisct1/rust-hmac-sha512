# hmac-sha512

A small, self-contained implementation of SHA512, HMAC-SHA512, SHA384, and HMAC-SHA384 in Rust.

[![Crates.io](https://img.shields.io/crates/v/hmac-sha512)](https://crates.io/crates/hmac-sha512)
[![Documentation](https://docs.rs/hmac-sha512/badge.svg)](https://docs.rs/hmac-sha512)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)

## Features

- Minimal dependencies
- `no_std` compatible for embedded systems
- Small code size with optional size optimizations
- Optional support for the `Digest` trait from the `digest` crate
- Constant-time verification for HMAC results to prevent timing attacks

## Optional Features

- `sha384` (enabled by default): Includes SHA384 and HMAC-SHA384 implementations
- `opt_size`: Optimizes for binary size at a slight performance cost (reduces text section size by ~75% with ~16% performance hit)
- `traits`: Enables support for the `Digest` trait from the `digest` crate
  - `traits09`: Support for `digest` crate v0.9.x
  - `traits010`: Support for `digest` crate v0.10.x

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
hmac-sha512 = "1.1.6"
```

### SHA512 Hashing

```rust
use hmac_sha512::Hash;

// Compute SHA512 hash
let hash = Hash::hash(b"message");
```

### HMAC-SHA512

```rust
use hmac_sha512::HMAC;

// Compute HMAC-SHA512
let mac = HMAC::mac(b"message", b"key");

// Verify HMAC-SHA512
let expected = [0u8; 64]; // Replace with actual expected MAC
let is_valid = HMAC::verify(b"message", b"key", &expected);
```

### SHA384 Hashing (when enabled)

```rust
use hmac_sha512::sha384::Hash;

// Compute SHA384 hash
let hash = Hash::hash(b"message");
```

### HMAC-SHA384 (when enabled)

```rust
use hmac_sha512::sha384::HMAC;

// Compute HMAC-SHA384
let mac = HMAC::mac(b"message", b"key");

// Verify HMAC-SHA384
let expected = [0u8; 48]; // Replace with actual expected MAC
let is_valid = HMAC::verify(b"message", b"key", &expected);
```

### With Digest Trait (when enabled)

```rust
use hmac_sha512::Hash;
use digest::Digest;  // Requires the digest crate

let mut hasher = Hash::new();
hasher.update(b"message");
let result = hasher.finalize();
```

## Building and Testing

```bash
# Build with default features
cargo build

# Build with release optimizations
cargo build --release

# Build with specific features
cargo build --features="traits"
cargo build --features="opt_size"
cargo build --no-default-features  # Excludes SHA384 support

# Run all tests
cargo test
```

## License

This project is licensed under the [ISC License](LICENSE).