# rust-hmac-sha512

A small, self-contained SHA512 and HMAC-SHA512 implementation in Rust.

Also includes SHA384 and HMAC-SHA384, that are just truncated versions of SHA512 with a different IV.

Optional features:

* `traits`: enable support for the `Digest` trait from the `digest` crate.
* `sha384`: includes support for SHA384 and HMAC-SHA384.