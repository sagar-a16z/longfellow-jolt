//! # P-256 (secp256r1 / NIST P-256) Inline Implementation for Jolt
//!
//! This crate provides custom RISC-V inline instructions for P-256 elliptic curve
//! field arithmetic, enabling efficient ECDSA signature verification inside the
//! Jolt zkVM.
//!
//! ## Architecture
//!
//! Each inline instruction verifies the algebraic identity:
//!
//! ```text
//!     a * b + w * p = 2^256 * w + c
//! ```
//!
//! where `c = a*b mod q` (the result), `w = floor(a*b/q)` (supplied as
//! non-deterministic advice), and `p = 2^256 - q`. The prover computes `w`
//! off-circuit; the in-circuit verification is a schoolbook multiplication
//! with carry propagation (~246 virtual instructions per field multiply).
//!
//! ## Inline Instructions (opcode=0x0B, funct7=0x07)
//!
//! | funct3 | Name         | Operation                     |
//! |--------|--------------|-------------------------------|
//! | 0x00   | P256_MULQ    | Base field (Fq) multiplication|
//! | 0x01   | P256_SQUAREQ | Base field (Fq) squaring      |
//! | 0x02   | P256_DIVQ    | Base field (Fq) division      |
//! | 0x04   | P256_MULR    | Scalar field (Fr) multiply    |
//! | 0x05   | P256_SQUARER | Scalar field (Fr) squaring    |
//! | 0x06   | P256_DIVR    | Scalar field (Fr) division    |
//!
//! ## P-256 vs secp256k1 Differences
//!
//! - **No GLV endomorphism**: P-256 does not have an efficiently computable
//!   endomorphism. Scalar multiplication uses standard 256-bit Shamir's trick
//!   instead of the 4x128-bit multi-scalar multiplication that secp256k1 uses.
//!
//! - **4-limb modular complement**: P-256's `p = 2^256 - q` has 4 nonzero
//!   64-bit limbs (vs secp256k1's 1 limb), resulting in ~44% more MAC
//!   operations per inline. Base field multiply: ~246 virtual instructions
//!   (vs secp256k1's ~170).
//!
//! - **Curve parameter a = -3**: P-256 uses `y^2 = x^3 - 3x + b` (vs
//!   secp256k1's `y^2 = x^3 + 7`). The doubling formula includes the `a`
//!   term, but this is just a free field addition.
//!
//! ## Performance
//!
//! Each P-256 ECDSA verification takes ~470,000 Jolt cycles using the inline
//! instructions, compared to ~4,300,000 cycles with the software-only p256
//! crate — a **9.1x improvement**. The secp256k1 inline achieves ~262,000
//! cycles per ECDSA due to GLV and the simpler prime structure.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use jolt_inlines_p256::{P256Fr, P256Point, ecdsa_verify, UnwrapOrSpoilProof};
//!
//! let z = P256Fr::from_u64_arr(&hash_limbs).unwrap_or_spoil_proof();
//! let r = P256Fr::from_u64_arr(&sig_r_limbs).unwrap_or_spoil_proof();
//! let s = P256Fr::from_u64_arr(&sig_s_limbs).unwrap_or_spoil_proof();
//! let q = P256Point::from_u64_arr(&pk_limbs).unwrap_or_spoil_proof();
//! ecdsa_verify(z, r, s, q).unwrap_or_spoil_proof();
//! ```

#![cfg_attr(not(feature = "host"), no_std)]

pub const INLINE_OPCODE: u32 = 0x0B;
pub const P256_FUNCT7: u32 = 0x07;

// base field (q) multiplication helper
// that is, given a and b in Fq, compute a 256-bit c such that ab - wq = c
pub const P256_MULQ_FUNCT3: u32 = 0x00;
pub const P256_MULQ_NAME: &str = "P256_MULQ";

// base field (q) square helper
// that is, given a in Fq, compute a 256-bit c such that a^2 - wq = c
pub const P256_SQUAREQ_FUNCT3: u32 = 0x01;
pub const P256_SQUAREQ_NAME: &str = "P256_SQUAREQ";

// base field (q) division helper
// that is, given a and b in Fq, compute a 256-bit c such that cb - wq = a
pub const P256_DIVQ_FUNCT3: u32 = 0x02;
pub const P256_DIVQ_NAME: &str = "P256_DIVQ";

// scalar field (r) multiplication helper
// that is, given a and b in Fr, compute a 256-bit c such that ab - wq = c
pub const P256_MULR_FUNCT3: u32 = 0x04;
pub const P256_MULR_NAME: &str = "P256_MULR";

// scalar field (r) square helper
// that is, given a in Fr, compute a 256-bit c such that a^2 - wq = c
pub const P256_SQUARER_FUNCT3: u32 = 0x05;
pub const P256_SQUARER_NAME: &str = "P256_SQUARER";

// scalar field (r) division helper
// that is, given a and b in Fr, compute a 256-bit c such that cb - wq = a
pub const P256_DIVR_FUNCT3: u32 = 0x06;
pub const P256_DIVR_NAME: &str = "P256_DIVR";

// ---------------------------------------------------------------------------
// P-256 curve parameters
// ---------------------------------------------------------------------------

/// P-256 base field modulus (little-endian u64 limbs)
/// p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
pub const P256_MODULUS: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// P-256 scalar field order (little-endian u64 limbs)
/// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
pub const P256_ORDER: [u64; 4] = [
    0xF3B9_CAC2_FC63_2551,
    0xBCE6_FAAD_A717_9E84,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
];

/// 2^256 - p (base field), for reduction: little-endian u64 limbs
/// Used as the "negative modulus" for Barrett-like reductions.
pub const P256_BASEFIELD_NEG_MODULUS: [u64; 4] = [
    0x0000_0000_0000_0001,
    0xFFFF_FFFF_0000_0000,
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFE,
];

/// 2^256 - n (scalar field), for reduction: little-endian u64 limbs
pub const P256_SCALARFIELD_NEG_ORDER: [u64; 4] = [
    0x0C46_353D_039C_DAAF,
    0x4319_0552_58E8_617B,
    0x0000_0000_0000_0000,
    0x0000_0000_FFFF_FFFF,
];

/// P-256 generator x-coordinate (little-endian u64 limbs)
/// Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
pub const P256_GENERATOR_X: [u64; 4] = [
    0xF4A1_3945_D898_C296,
    0x7703_7D81_2DEB_33A0,
    0xF8BC_E6E5_63A4_40F2,
    0x6B17_D1F2_E12C_4247,
];

/// P-256 generator y-coordinate (little-endian u64 limbs)
/// Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
pub const P256_GENERATOR_Y: [u64; 4] = [
    0xCBB6_4068_37BF_51F5,
    0x2BCE_3357_6B31_5ECE,
    0x8EE7_EB4A_7C0F_9E16,
    0x4FE3_42E2_FE1A_7F9B,
];

/// P-256 curve parameter b (little-endian u64 limbs)
/// b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
pub const P256_CURVE_B: [u64; 4] = [
    0x3BCE_3C3E_27D2_604B,
    0x651D_06B0_CC53_B0F6,
    0xB3EB_BD55_7698_86BC,
    0x5AC6_35D8_AA3A_93E7,
];

pub mod sdk;
pub use sdk::*;

#[cfg(feature = "host")]
pub mod sequence_builder;

#[cfg(feature = "host")]
mod host;
#[cfg(feature = "host")]
pub use host::*;

#[cfg(all(test, feature = "host"))]
mod tests;
