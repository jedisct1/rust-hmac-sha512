//! A small, self-contained SHA512 and HMAC-SHA512 implementation
//! (C) Frank Denis <fdenis [at] fastly [dot] com>, public domain

#![no_std]
#![allow(
    non_snake_case,
    clippy::cast_lossless,
    clippy::eq_op,
    clippy::identity_op,
    clippy::many_single_char_names,
    clippy::unreadable_literal
)]

pub const BLOCKBYTES: usize = 128;
pub const BYTES: usize = 64;

#[inline(always)]
fn load_be(base: &[u8], offset: usize) -> u64 {
    let addr = &base[offset..];
    (addr[7] as u64)
        | (addr[6] as u64) << 8
        | (addr[5] as u64) << 16
        | (addr[4] as u64) << 24
        | (addr[3] as u64) << 32
        | (addr[2] as u64) << 40
        | (addr[1] as u64) << 48
        | (addr[0] as u64) << 56
}

#[inline(always)]
fn store_be(base: &mut [u8], offset: usize, x: u64) {
    let addr = &mut base[offset..];
    addr[7] = x as u8;
    addr[6] = (x >> 8) as u8;
    addr[5] = (x >> 16) as u8;
    addr[4] = (x >> 24) as u8;
    addr[3] = (x >> 32) as u8;
    addr[2] = (x >> 40) as u8;
    addr[1] = (x >> 48) as u8;
    addr[0] = (x >> 56) as u8;
}

struct W([u64; 16]);

#[derive(Copy, Clone)]
struct State([u64; 8]);

impl W {
    fn new(input: &[u8]) -> Self {
        let mut w = [0u64; 16];
        for (i, e) in w.iter_mut().enumerate() {
            *e = load_be(input, i * 8)
        }
        W(w)
    }

    #[inline(always)]
    fn Ch(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn Maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn Sigma0(x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    #[inline(always)]
    fn Sigma1(x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    #[inline(always)]
    fn sigma0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }

    #[inline(always)]
    fn sigma1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }

    #[cfg_attr(feature = "opt_size", inline(never))]
    #[cfg_attr(not(feature = "opt_size"), inline(always))]
    fn M(&mut self, a: usize, b: usize, c: usize, d: usize) {
        let w = &mut self.0;
        w[a] = w[a]
            .wrapping_add(Self::sigma1(w[b]))
            .wrapping_add(w[c])
            .wrapping_add(Self::sigma0(w[d]));
    }

    #[inline]
    fn expand(&mut self) {
        self.M(0, (0 + 14) & 15, (0 + 9) & 15, (0 + 1) & 15);
        self.M(1, (1 + 14) & 15, (1 + 9) & 15, (1 + 1) & 15);
        self.M(2, (2 + 14) & 15, (2 + 9) & 15, (2 + 1) & 15);
        self.M(3, (3 + 14) & 15, (3 + 9) & 15, (3 + 1) & 15);
        self.M(4, (4 + 14) & 15, (4 + 9) & 15, (4 + 1) & 15);
        self.M(5, (5 + 14) & 15, (5 + 9) & 15, (5 + 1) & 15);
        self.M(6, (6 + 14) & 15, (6 + 9) & 15, (6 + 1) & 15);
        self.M(7, (7 + 14) & 15, (7 + 9) & 15, (7 + 1) & 15);
        self.M(8, (8 + 14) & 15, (8 + 9) & 15, (8 + 1) & 15);
        self.M(9, (9 + 14) & 15, (9 + 9) & 15, (9 + 1) & 15);
        self.M(10, (10 + 14) & 15, (10 + 9) & 15, (10 + 1) & 15);
        self.M(11, (11 + 14) & 15, (11 + 9) & 15, (11 + 1) & 15);
        self.M(12, (12 + 14) & 15, (12 + 9) & 15, (12 + 1) & 15);
        self.M(13, (13 + 14) & 15, (13 + 9) & 15, (13 + 1) & 15);
        self.M(14, (14 + 14) & 15, (14 + 9) & 15, (14 + 1) & 15);
        self.M(15, (15 + 14) & 15, (15 + 9) & 15, (15 + 1) & 15);
    }

    #[cfg_attr(feature = "opt_size", inline(never))]
    #[cfg_attr(not(feature = "opt_size"), inline(always))]
    fn F(&mut self, state: &mut State, i: usize, k: u64) {
        let t = &mut state.0;
        t[(16 - i + 7) & 7] = t[(16 - i + 7) & 7]
            .wrapping_add(Self::Sigma1(t[(16 - i + 4) & 7]))
            .wrapping_add(Self::Ch(
                t[(16 - i + 4) & 7],
                t[(16 - i + 5) & 7],
                t[(16 - i + 6) & 7],
            ))
            .wrapping_add(k)
            .wrapping_add(self.0[i]);
        t[(16 - i + 3) & 7] = t[(16 - i + 3) & 7].wrapping_add(t[(16 - i + 7) & 7]);
        t[(16 - i + 7) & 7] = t[(16 - i + 7) & 7]
            .wrapping_add(Self::Sigma0(t[(16 - i + 0) & 7]))
            .wrapping_add(Self::Maj(
                t[(16 - i + 0) & 7],
                t[(16 - i + 1) & 7],
                t[(16 - i + 2) & 7],
            ));
    }

    fn G(&mut self, state: &mut State, s: usize) {
        const ROUND_CONSTANTS: [u64; 80] = [
            0x428a2f98d728ae22,
            0x7137449123ef65cd,
            0xb5c0fbcfec4d3b2f,
            0xe9b5dba58189dbbc,
            0x3956c25bf348b538,
            0x59f111f1b605d019,
            0x923f82a4af194f9b,
            0xab1c5ed5da6d8118,
            0xd807aa98a3030242,
            0x12835b0145706fbe,
            0x243185be4ee4b28c,
            0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f,
            0x80deb1fe3b1696b1,
            0x9bdc06a725c71235,
            0xc19bf174cf692694,
            0xe49b69c19ef14ad2,
            0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5,
            0x240ca1cc77ac9c65,
            0x2de92c6f592b0275,
            0x4a7484aa6ea6e483,
            0x5cb0a9dcbd41fbd4,
            0x76f988da831153b5,
            0x983e5152ee66dfab,
            0xa831c66d2db43210,
            0xb00327c898fb213f,
            0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2,
            0xd5a79147930aa725,
            0x06ca6351e003826f,
            0x142929670a0e6e70,
            0x27b70a8546d22ffc,
            0x2e1b21385c26c926,
            0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df,
            0x650a73548baf63de,
            0x766a0abb3c77b2a8,
            0x81c2c92e47edaee6,
            0x92722c851482353b,
            0xa2bfe8a14cf10364,
            0xa81a664bbc423001,
            0xc24b8b70d0f89791,
            0xc76c51a30654be30,
            0xd192e819d6ef5218,
            0xd69906245565a910,
            0xf40e35855771202a,
            0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8,
            0x1e376c085141ab53,
            0x2748774cdf8eeb99,
            0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63,
            0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc,
            0x78a5636f43172f60,
            0x84c87814a1f0ab72,
            0x8cc702081a6439ec,
            0x90befffa23631e28,
            0xa4506cebde82bde9,
            0xbef9a3f7b2c67915,
            0xc67178f2e372532b,
            0xca273eceea26619c,
            0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e,
            0xf57d4f7fee6ed178,
            0x06f067aa72176fba,
            0x0a637dc5a2c898a6,
            0x113f9804bef90dae,
            0x1b710b35131c471b,
            0x28db77f523047d84,
            0x32caab7b40c72493,
            0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6,
            0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec,
            0x6c44198c4a475817,
        ];
        let rc = &ROUND_CONSTANTS[s * 16..];
        self.F(state, 0, rc[0]);
        self.F(state, 1, rc[1]);
        self.F(state, 2, rc[2]);
        self.F(state, 3, rc[3]);
        self.F(state, 4, rc[4]);
        self.F(state, 5, rc[5]);
        self.F(state, 6, rc[6]);
        self.F(state, 7, rc[7]);
        self.F(state, 8, rc[8]);
        self.F(state, 9, rc[9]);
        self.F(state, 10, rc[10]);
        self.F(state, 11, rc[11]);
        self.F(state, 12, rc[12]);
        self.F(state, 13, rc[13]);
        self.F(state, 14, rc[14]);
        self.F(state, 15, rc[15]);
    }
}

impl State {
    fn new() -> Self {
        const IV: [u8; 64] = [
            0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85, 0x84, 0xca,
            0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a,
            0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05,
            0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b,
            0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79,
        ];
        let mut t = [0u64; 8];
        for (i, e) in t.iter_mut().enumerate() {
            *e = load_be(&IV, i * 8)
        }
        State(t)
    }

    #[inline(always)]
    fn add(&mut self, x: &State) {
        let sx = &mut self.0;
        let ex = &x.0;
        sx[0] = sx[0].wrapping_add(ex[0]);
        sx[1] = sx[1].wrapping_add(ex[1]);
        sx[2] = sx[2].wrapping_add(ex[2]);
        sx[3] = sx[3].wrapping_add(ex[3]);
        sx[4] = sx[4].wrapping_add(ex[4]);
        sx[5] = sx[5].wrapping_add(ex[5]);
        sx[6] = sx[6].wrapping_add(ex[6]);
        sx[7] = sx[7].wrapping_add(ex[7]);
    }

    fn store(&self, out: &mut [u8]) {
        for (i, &e) in self.0.iter().enumerate() {
            store_be(out, i * 8, e);
        }
    }

    fn blocks(&mut self, mut input: &[u8]) -> usize {
        let mut t = *self;
        let mut inlen = input.len();
        while inlen >= 128 {
            let mut w = W::new(input);
            w.G(&mut t, 0);
            w.expand();
            w.G(&mut t, 1);
            w.expand();
            w.G(&mut t, 2);
            w.expand();
            w.G(&mut t, 3);
            w.expand();
            w.G(&mut t, 4);
            t.add(self);
            self.0 = t.0;
            input = &input[128..];
            inlen -= 128;
        }
        inlen
    }
}

#[derive(Copy, Clone)]
pub struct Hash {
    state: State,
    w: [u8; 128],
    r: usize,
    len: usize,
}

impl Hash {
    pub fn new() -> Hash {
        Hash {
            state: State::new(),
            r: 0,
            w: [0u8; 128],
            len: 0,
        }
    }

    fn _update<T: AsRef<[u8]>>(&mut self, input: T) {
        let input = input.as_ref();
        let mut n = input.len();
        self.len += n;
        let av = 128 - self.r;
        let tc = ::core::cmp::min(n, av);
        self.w[self.r..self.r + tc].copy_from_slice(&input[0..tc]);
        self.r += tc;
        n -= tc;
        let pos = tc;
        if self.r == 128 {
            self.state.blocks(&self.w);
            self.r = 0;
        }
        if self.r == 0 && n > 0 {
            let rb = self.state.blocks(&input[pos..]);
            if rb > 0 {
                self.w[..rb].copy_from_slice(&input[pos + n - rb..]);
                self.r = rb;
            }
        }
    }

    /// Absorb content
    pub fn update<T: AsRef<[u8]>>(&mut self, input: T) {
        self._update(input)
    }

    /// Compute SHA512(absorbed content)
    pub fn finalize(mut self) -> [u8; 64] {
        let mut padded = [0u8; 256];
        padded[..self.r].copy_from_slice(&self.w[..self.r]);
        padded[self.r] = 0x80;
        let r = if self.r < 112 { 128 } else { 256 };
        let bits = self.len * 8;
        for i in 0..8 {
            padded[r - 8 + i] = (bits as u64 >> (56 - i * 8)) as u8;
        }
        self.state.blocks(&padded[..r]);
        let mut out = [0u8; 64];
        self.state.store(&mut out);
        out
    }

    /// Compute SHA512(`input`)
    pub fn hash<T: AsRef<[u8]>>(input: T) -> [u8; 64] {
        let mut h = Hash::new();
        h.update(input);
        h.finalize()
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "traits09")]
mod digest_trait {
    use digest09::consts::{U128, U64};
    use digest09::{BlockInput, FixedOutputDirty, Output, Reset, Update};

    use super::Hash;

    impl BlockInput for Hash {
        type BlockSize = U128;
    }

    impl Update for Hash {
        fn update(&mut self, input: impl AsRef<[u8]>) {
            self._update(input);
        }
    }

    impl FixedOutputDirty for Hash {
        type OutputSize = U64;

        fn finalize_into_dirty(&mut self, out: &mut Output<Self>) {
            let h = self.finalize();
            out.copy_from_slice(&h);
        }
    }

    impl Reset for Hash {
        fn reset(&mut self) {
            *self = Self::new();
        }
    }
}

/// Wrapped `Hash` type for the `Digest` trait.
#[cfg(feature = "traits010")]
pub type WrappedHash = digest010::core_api::CoreWrapper<Hash>;

#[cfg(feature = "traits010")]
mod digest_trait010 {
    use core::fmt;

    use digest010::{
        block_buffer::Eager,
        const_oid::{AssociatedOid, ObjectIdentifier},
        consts::{U128, U64},
        core_api::{
            AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, FixedOutputCore,
            OutputSizeUser, Reset, UpdateCore,
        },
        FixedOutput, FixedOutputReset, HashMarker, Output, Update,
    };

    use super::Hash;

    impl AssociatedOid for Hash {
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
    }

    impl AlgorithmName for Hash {
        fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Sha512")
        }
    }

    impl HashMarker for Hash {}

    impl BufferKindUser for Hash {
        type BufferKind = Eager;
    }

    impl BlockSizeUser for Hash {
        type BlockSize = U128;
    }

    impl OutputSizeUser for Hash {
        type OutputSize = U64;
    }

    impl UpdateCore for Hash {
        #[inline]
        fn update_blocks(&mut self, blocks: &[Block<Self>]) {
            for block in blocks {
                self._update(block);
            }
        }
    }

    impl Update for Hash {
        #[inline]
        fn update(&mut self, data: &[u8]) {
            self._update(data);
        }
    }

    impl FixedOutputCore for Hash {
        fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
            self._update(buffer.get_data());
            let h = self.finalize();
            out.copy_from_slice(&h);
        }
    }

    impl FixedOutput for Hash {
        fn finalize_into(self, out: &mut Output<Self>) {
            let h = self.finalize();
            out.copy_from_slice(&h);
        }
    }

    impl Reset for Hash {
        fn reset(&mut self) {
            *self = Self::new()
        }
    }

    impl FixedOutputReset for Hash {
        fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
            self.finalize_into(out);
            self.reset();
        }
    }
}

pub struct HMAC;

impl HMAC {
    /// Compute HMAC-SHA512(`input`, `k`)
    pub fn mac<T: AsRef<[u8]>, U: AsRef<[u8]>>(input: T, k: U) -> [u8; 64] {
        let input = input.as_ref();
        let k = k.as_ref();
        let mut hk = [0u8; 64];
        let k2 = if k.len() > 128 {
            hk.copy_from_slice(&Hash::hash(k));
            &hk
        } else {
            k
        };
        let mut ih = Hash::new();
        let mut padded = [0x36; 128];
        for (p, &k) in padded.iter_mut().zip(k2.iter()) {
            *p ^= k;
        }
        ih.update(&padded[..]);
        ih.update(input);

        let mut oh = Hash::new();
        padded = [0x5c; 128];
        for (p, &k) in padded.iter_mut().zip(k2.iter()) {
            *p ^= k;
        }
        oh.update(&padded[..]);
        oh.update(&ih.finalize()[..]);
        oh.finalize()
    }
}

#[cfg(feature = "sha384")]
pub mod sha384 {
    use super::load_be;

    fn new_state() -> super::State {
        const IV: [u8; 64] = [
            0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8, 0x62, 0x9a, 0x29, 0x2a, 0x36, 0x7c,
            0xd5, 0x07, 0x91, 0x59, 0x01, 0x5a, 0x30, 0x70, 0xdd, 0x17, 0x15, 0x2f, 0xec, 0xd8,
            0xf7, 0x0e, 0x59, 0x39, 0x67, 0x33, 0x26, 0x67, 0xff, 0xc0, 0x0b, 0x31, 0x8e, 0xb4,
            0x4a, 0x87, 0x68, 0x58, 0x15, 0x11, 0xdb, 0x0c, 0x2e, 0x0d, 0x64, 0xf9, 0x8f, 0xa7,
            0x47, 0xb5, 0x48, 0x1d, 0xbe, 0xfa, 0x4f, 0xa4,
        ];
        let mut t = [0u64; 8];
        for (i, e) in t.iter_mut().enumerate() {
            *e = load_be(&IV, i * 8)
        }
        super::State(t)
    }

    #[derive(Copy, Clone)]
    pub struct Hash(super::Hash);

    impl Hash {
        pub fn new() -> Hash {
            Hash(super::Hash {
                state: new_state(),
                r: 0,
                w: [0u8; 128],
                len: 0,
            })
        }

        fn _update<T: AsRef<[u8]>>(&mut self, input: T) {
            self.0.update(input)
        }

        /// Absorb content
        pub fn update<T: AsRef<[u8]>>(&mut self, input: T) {
            self._update(input)
        }

        /// Compute SHA384(absorbed content)
        pub fn finalize(self) -> [u8; 48] {
            let mut h = [0u8; 48];
            h.copy_from_slice(&self.0.finalize()[..48]);
            h
        }

        /// Compute SHA384(`input`)
        pub fn hash<T: AsRef<[u8]>>(input: T) -> [u8; 48] {
            let mut h = Hash::new();
            h.update(input);
            h.finalize()
        }
    }

    impl Default for Hash {
        fn default() -> Self {
            Self::new()
        }
    }

    pub struct HMAC;

    impl HMAC {
        /// Compute HMAC-SHA384(`input`, `k`)
        pub fn mac<T: AsRef<[u8]>, U: AsRef<[u8]>>(input: T, k: U) -> [u8; 48] {
            let input = input.as_ref();
            let k = k.as_ref();
            let mut hk = [0u8; 48];
            let k2 = if k.len() > 128 {
                hk.copy_from_slice(&Hash::hash(k));
                &hk
            } else {
                k
            };
            let mut padded = [0x36; 128];
            for (p, &k) in padded.iter_mut().zip(k2.iter()) {
                *p ^= k;
            }
            let mut ih = Hash::new();
            ih.update(&padded[..]);
            ih.update(input);

            for p in padded.iter_mut() {
                *p ^= 0x6a;
            }
            let mut oh = Hash::new();
            oh.update(&padded[..]);
            oh.update(&ih.finalize()[..]);
            oh.finalize()
        }
    }

    #[cfg(feature = "traits09")]
    mod digest_trait09 {
        use digest09::consts::{U128, U48};
        use digest09::{BlockInput, FixedOutputDirty, Output, Reset, Update};

        use super::Hash;

        impl BlockInput for Hash {
            type BlockSize = U128;
        }

        impl Update for Hash {
            fn update(&mut self, input: impl AsRef<[u8]>) {
                self._update(input);
            }
        }

        impl FixedOutputDirty for Hash {
            type OutputSize = U48;

            fn finalize_into_dirty(&mut self, out: &mut Output<Self>) {
                let h = self.finalize();
                out.copy_from_slice(&h);
            }
        }

        impl Reset for Hash {
            fn reset(&mut self) {
                *self = Self::new();
            }
        }
    }

    /// Wrapped `Hash` type for the `Digest` trait.
    #[cfg(feature = "traits010")]
    pub type WrappedHash = digest010::core_api::CoreWrapper<Hash>;

    #[cfg(feature = "traits010")]
    mod digest_trait010 {
        use core::fmt;

        use digest010::{
            block_buffer::Eager,
            const_oid::{AssociatedOid, ObjectIdentifier},
            consts::{U128, U48},
            core_api::{
                AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, FixedOutputCore,
                OutputSizeUser, Reset, UpdateCore,
            },
            FixedOutput, FixedOutputReset, HashMarker, Output, Update,
        };

        use super::Hash;

        impl AssociatedOid for Hash {
            const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
        }

        impl AlgorithmName for Hash {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("Sha384")
            }
        }

        impl HashMarker for Hash {}

        impl BufferKindUser for Hash {
            type BufferKind = Eager;
        }

        impl BlockSizeUser for Hash {
            type BlockSize = U128;
        }

        impl OutputSizeUser for Hash {
            type OutputSize = U48;
        }

        impl UpdateCore for Hash {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self._update(block);
                }
            }
        }

        impl Update for Hash {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self._update(data);
            }
        }

        impl FixedOutputCore for Hash {
            fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
                self._update(buffer.get_data());
                let h = self.finalize();
                out.copy_from_slice(&h);
            }
        }

        impl FixedOutput for Hash {
            fn finalize_into(self, out: &mut Output<Self>) {
                let h = self.finalize();
                out.copy_from_slice(&h);
            }
        }

        impl Reset for Hash {
            fn reset(&mut self) {
                *self = Self::new()
            }
        }

        impl FixedOutputReset for Hash {
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                self.finalize_into(out);
                self.reset();
            }
        }
    }
}

#[test]
fn main() {
    let h = HMAC::mac([], [0u8; 32]);
    assert_eq!(
        h.to_vec(),
        [
            185, 54, 206, 232, 108, 159, 135, 170, 93, 60, 111, 46, 132, 203, 90, 66, 57, 165, 254,
            80, 72, 10, 110, 198, 107, 112, 171, 91, 31, 74, 198, 115, 12, 108, 81, 84, 33, 179,
            39, 236, 29, 105, 64, 46, 83, 223, 180, 154, 215, 56, 30, 176, 103, 179, 56, 253, 123,
            12, 178, 34, 71, 34, 93, 71
        ]
        .to_vec()
    );

    let h = HMAC::mac([42u8; 69], []);
    assert_eq!(
        h.to_vec(),
        [
            56, 224, 189, 205, 65, 104, 107, 85, 241, 188, 253, 35, 238, 174, 69, 191, 206, 183,
            205, 71, 196, 180, 56, 122, 106, 55, 136, 7, 208, 183, 99, 67, 229, 213, 255, 154, 107,
            136, 11, 154, 11, 187, 75, 214, 172, 117, 14, 248, 189, 48, 193, 62, 37, 208, 159, 227,
            115, 59, 54, 91, 143, 143, 254, 220
        ]
        .to_vec()
    );

    let h = HMAC::mac([69u8; 250], [42u8; 50]);
    assert_eq!(
        h.to_vec(),
        [
            122, 111, 187, 241, 74, 194, 22, 106, 95, 206, 80, 215, 75, 207, 11, 78, 37, 94, 125,
            110, 125, 42, 254, 103, 224, 21, 112, 247, 233, 229, 36, 200, 58, 238, 211, 156, 121,
            231, 15, 202, 128, 90, 126, 179, 188, 37, 194, 106, 223, 218, 45, 211, 149, 91, 131,
            226, 117, 184, 175, 85, 224, 197, 82, 175
        ]
        .to_vec()
    );

    let h = HMAC::mac(b"Hi There", [0x0b; 20]);
    assert_eq!(
        h.to_vec(),
        [
            135, 170, 124, 222, 165, 239, 97, 157, 79, 240, 180, 36, 26, 29, 108, 176, 35, 121,
            244, 226, 206, 78, 194, 120, 122, 208, 179, 5, 69, 225, 124, 222, 218, 168, 51, 183,
            214, 184, 167, 2, 3, 139, 39, 78, 174, 163, 244, 228, 190, 157, 145, 78, 235, 97, 241,
            112, 46, 105, 108, 32, 58, 18, 104, 84
        ]
        .to_vec()
    );
}

#[cfg(feature = "sha384")]
#[test]
fn sha384() {
    let h = sha384::HMAC::mac(b"Hi There", [0x0b; 20]);
    assert_eq!(
        h.to_vec(),
        [
            175, 208, 57, 68, 216, 72, 149, 98, 107, 8, 37, 244, 171, 70, 144, 127, 21, 249, 218,
            219, 228, 16, 30, 198, 130, 170, 3, 76, 124, 235, 197, 156, 250, 234, 158, 169, 7, 110,
            222, 127, 74, 241, 82, 232, 178, 250, 156, 182
        ]
        .to_vec()
    );
}
