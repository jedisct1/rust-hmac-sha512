# hmac-sha512

A small, self-contained SHA512, HMAC-SHA512, HKDF-SHA512, SHA384, and HMAC-SHA384 implementation in Rust.

[![Crates.io](https://img.shields.io/crates/v/hmac-sha512)](https://crates.io/crates/hmac-sha512)
[![Documentation](https://docs.rs/hmac-sha512/badge.svg)](https://docs.rs/hmac-sha512)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)

## Features

- Pure Rust implementation
- Minimal dependencies
- `no_std` compatible for embedded systems
- Both one-shot and streaming APIs for HMAC
- HKDF key derivation (RFC 5869)
- Constant-time verification to prevent timing attacks
- Optional size optimizations

## Optional Features

- `sha384` (enabled by default): Includes SHA384 and HMAC-SHA384 implementations
- `opt_size`: Optimizes for binary size at a slight performance cost (reduces text section size by ~75% with ~16% performance hit)
- `traits09`: Support for `Digest` trait from `digest` crate v0.9.x
- `traits010`: Support for `Digest` trait from `digest` crate v0.10.x
- `traits011`: Support for `Digest` trait from `digest` crate v0.11.x

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
hmac-sha512 = "1.1"
```

### SHA512 Hashing

```rust
use hmac_sha512::Hash;

// One-shot hashing
let hash = Hash::hash(b"message");

// Incremental hashing
let mut hasher = Hash::new();
hasher.update(b"hello ");
hasher.update(b"world");
let hash = hasher.finalize();
```

### HMAC-SHA512

```rust
use hmac_sha512::HMAC;

// One-shot HMAC
let mac = HMAC::mac(b"message", b"key");

// Incremental HMAC
let mut hmac = HMAC::new(b"key");
hmac.update(b"message part 1");
hmac.update(b"message part 2");
let mac = hmac.finalize();

// Constant-time verification (one-shot)
let expected = HMAC::mac(b"message", b"key");
let is_valid = HMAC::verify(b"message", b"key", &expected);

// Constant-time verification (streaming)
let mut hmac = HMAC::new(b"key");
hmac.update(b"message");
assert!(hmac.finalize_verify(&expected));
```

### HKDF-SHA512

HKDF (HMAC-based Key Derivation Function) as defined in RFC 5869.

```rust
use hmac_sha512::HKDF;

// Extract a pseudorandom key from input keying material
let prk = HKDF::extract(b"salt", b"input key material");

// Expand the pseudorandom key to the desired output length
let mut output = [0u8; 128];
HKDF::expand(&mut output, prk, b"application info");
```

### SHA384 Hashing (when enabled)

```rust
use hmac_sha512::sha384::Hash;

let hash = Hash::hash(b"message");
```

### HMAC-SHA384 (when enabled)

```rust
use hmac_sha512::sha384::HMAC;

let mac = HMAC::mac(b"message", b"key");

let expected = [0u8; 48]; // Replace with actual expected MAC
let is_valid = HMAC::verify(b"message", b"key", &expected);
```

### With Digest Trait

```rust
use hmac_sha512::Hash;
use digest::Digest;  // Requires enabling traits feature

let mut hasher = Hash::new();
hasher.update(b"message");
let result = hasher.finalize();
```

## Building and Testing

```bash
# Build with default features
cargo build

# Build with all features
cargo build --all-features

# Build without SHA384 support
cargo build --no-default-features

# Run all tests
cargo test --all-features
```

## License

This project is licensed under the [ISC License](LICENSE).
