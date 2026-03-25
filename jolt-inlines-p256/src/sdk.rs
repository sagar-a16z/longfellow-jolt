//! P-256 (NIST P-256 / secp256r1) operations optimized for Jolt zkVM.
//!
//! Provides `P256Fq` (base field) and `P256Fr` (scalar field) types that wrap
//! `[u64; 4]` limbs in standard (non-Montgomery) form.  Multiplication, squaring,
//! and division are dispatched to custom RISC-V inline instructions on guest builds,
//! and to `num_bigint::BigUint` arithmetic on host builds.  Addition, subtraction,
//! negation, doubling, and tripling are implemented as pure integer arithmetic
//! (no arkworks dependency, since there is no `ark-p256` crate).

#[cfg(feature = "host")]
use num_bigint::BigUint;

extern crate alloc;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// P-256 curve constants (little-endian u64 limbs)
// ---------------------------------------------------------------------------

/// Base field modulus p = 2^256 - 2^224 + 2^192 + 2^96 - 1
/// Big-endian hex: FFFFFFFF00000001 0000000000000000 00000000FFFFFFFF FFFFFFFFFFFFFFFF
pub const P256_MODULUS: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

/// Base field modulus as little-endian bytes (for BigUint conversions)
pub const P256_MODULUS_BYTES: [u8; 32] = limbs_to_le_bytes(P256_MODULUS);

/// Scalar field order n
/// Big-endian hex: FFFFFFFF00000000 FFFFFFFFFFFFFFFF BCE6FAADA7179E84 F3B9CAC2FC632551
pub const P256_ORDER: [u64; 4] = [
    0xF3B9CAC2FC632551,
    0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
];

/// Scalar field order as little-endian bytes (for BigUint conversions)
pub const P256_ORDER_BYTES: [u8; 32] = limbs_to_le_bytes(P256_ORDER);

/// Curve parameter b
/// Big-endian hex: 5AC635D8AA3A93E7 B3EBBD55769886BC 651D06B0CC53B0F6 3BCE3C3E27D2604B
pub const P256_B: [u64; 4] = [
    0x3BCE3C3E27D2604B,
    0x651D06B0CC53B0F6,
    0xB3EBBD55769886BC,
    0x5AC635D8AA3A93E7,
];

/// Generator x-coordinate
/// Big-endian hex: 6B17D1F2E12C4247 F8BCE6E563A440F2 77037D812DEB33A0 F4A13945D898C296
pub const P256_GX: [u64; 4] = [
    0xF4A13945D898C296,
    0x77037D812DEB33A0,
    0xF8BCE6E563A440F2,
    0x6B17D1F2E12C4247,
];

/// Generator y-coordinate
/// Big-endian hex: 4FE342E2FE1A7F9B 8EE7EB4A7C0F9E16 2BCE33576B315ECE CBB6406837BF51F5
pub const P256_GY: [u64; 4] = [
    0xCBB6406837BF51F5,
    0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16,
    0x4FE342E2FE1A7F9B,
];

// ---------------------------------------------------------------------------
// Compile-time helper: convert [u64; 4] limbs to [u8; 32] little-endian
// ---------------------------------------------------------------------------
const fn limbs_to_le_bytes(limbs: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 4 {
        let bytes = limbs[i].to_le_bytes();
        let base = i * 8;
        let mut j = 0;
        while j < 8 {
            out[base + j] = bytes[j];
            j += 1;
        }
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Runtime helpers: convert between [u64; 4] and BigUint (host only)
// ---------------------------------------------------------------------------

#[cfg(feature = "host")]
fn limbs_to_biguint(limbs: &[u64; 4]) -> BigUint {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        let le = limbs[i].to_le_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&le);
    }
    BigUint::from_bytes_le(&bytes)
}

#[cfg(feature = "host")]
fn biguint_to_limbs(n: &BigUint) -> [u64; 4] {
    let bytes = n.to_bytes_le();
    let mut padded = [0u8; 32];
    let len = bytes.len().min(32);
    padded[..len].copy_from_slice(&bytes[..len]);
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&padded[i * 8..(i + 1) * 8]);
        limbs[i] = u64::from_le_bytes(buf);
    }
    limbs
}

// ---------------------------------------------------------------------------
// Canonicality checks
// ---------------------------------------------------------------------------

/// Returns `true` iff `x >= p` (base field modulus), i.e., `x` is non-canonical.
///
/// P-256 modulus limbs (little-endian):
///   [0] = 0xFFFFFFFFFFFFFFFF
///   [1] = 0x00000000FFFFFFFF
///   [2] = 0x0000000000000000
///   [3] = 0xFFFFFFFF00000001
///
/// Because the limbs have mixed values, we need a full top-down comparison.
#[inline(always)]
fn is_fq_non_canonical(x: &[u64; 4]) -> bool {
    if x[3] < P256_MODULUS[3] {
        return false;
    } else if x[3] > P256_MODULUS[3] {
        return true;
    }
    // x[3] == P256_MODULUS[3]
    if x[2] < P256_MODULUS[2] {
        return false;
    } else if x[2] > P256_MODULUS[2] {
        return true;
    }
    // x[2] == P256_MODULUS[2] == 0
    if x[1] < P256_MODULUS[1] {
        return false;
    } else if x[1] > P256_MODULUS[1] {
        return true;
    }
    // x[1] == P256_MODULUS[1]
    x[0] >= P256_MODULUS[0]
}

/// Returns `true` iff `x >= n` (scalar field order), i.e., `x` is non-canonical.
///
/// P-256 order limbs (little-endian):
///   [0] = 0xF3B9CAC2FC632551
///   [1] = 0xBCE6FAADA7179E84
///   [2] = 0xFFFFFFFFFFFFFFFF
///   [3] = 0xFFFFFFFF00000000
///
/// Full top-down comparison since limbs have mixed values.
#[inline(always)]
fn is_fr_non_canonical(x: &[u64; 4]) -> bool {
    if x[3] < P256_ORDER[3] {
        return false;
    } else if x[3] > P256_ORDER[3] {
        return true;
    }
    // x[3] == P256_ORDER[3]
    if x[2] < P256_ORDER[2] {
        return false;
    } else if x[2] > P256_ORDER[2] {
        return true;
    }
    // x[2] == P256_ORDER[2] == 0xFFFFFFFFFFFFFFFF
    if x[1] < P256_ORDER[1] {
        return false;
    } else if x[1] > P256_ORDER[1] {
        return true;
    }
    // x[1] == P256_ORDER[1]
    x[0] >= P256_ORDER[0]
}

// ---------------------------------------------------------------------------
// Pure-integer field arithmetic helpers (no arkworks)
// ---------------------------------------------------------------------------

/// Add with carry: a + b + carry_in -> (sum, carry_out)
#[inline(always)]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let wide = a as u128 + b as u128 + carry as u128;
    (wide as u64, (wide >> 64) as u64)
}

/// Subtract with borrow: a - b - borrow_in -> (diff, borrow_out)
#[inline(always)]
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let wide = (a as u128).wrapping_sub(b as u128).wrapping_sub(borrow as u128);
    (wide as u64, ((wide >> 64) & 1) as u64)
}

/// r = a + b mod modulus.  Both a and b must be < modulus.
#[inline(always)]
fn add_mod(a: &[u64; 4], b: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let (r0, c) = adc(a[0], b[0], 0);
    let (r1, c) = adc(a[1], b[1], c);
    let (r2, c) = adc(a[2], b[2], c);
    let (r3, c) = adc(a[3], b[3], c);

    // Try subtracting modulus; if underflow we keep the original sum
    let (s0, bw) = sbb(r0, modulus[0], 0);
    let (s1, bw) = sbb(r1, modulus[1], bw);
    let (s2, bw) = sbb(r2, modulus[2], bw);
    let (s3, bw) = sbb(r3, modulus[3], bw);

    // If there was a carry from the addition (c != 0) then sum >= 2^256 > modulus,
    // so the subtraction is valid.  If c == 0 but no borrow from subtraction (bw == 0),
    // the subtraction is also valid.  Otherwise keep the un-subtracted value.
    let use_sub = c != 0 || bw == 0;
    if use_sub {
        [s0, s1, s2, s3]
    } else {
        [r0, r1, r2, r3]
    }
}

/// r = a - b mod modulus.  Both a and b must be < modulus.
#[inline(always)]
fn sub_mod(a: &[u64; 4], b: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let (r0, bw) = sbb(a[0], b[0], 0);
    let (r1, bw) = sbb(a[1], b[1], bw);
    let (r2, bw) = sbb(a[2], b[2], bw);
    let (r3, bw) = sbb(a[3], b[3], bw);

    // If there was a borrow, add modulus back
    if bw != 0 {
        let (s0, c) = adc(r0, modulus[0], 0);
        let (s1, c) = adc(r1, modulus[1], c);
        let (s2, c) = adc(r2, modulus[2], c);
        let (s3, _) = adc(r3, modulus[3], c);
        [s0, s1, s2, s3]
    } else {
        [r0, r1, r2, r3]
    }
}

/// r = -a mod modulus.  a must be < modulus.
#[inline(always)]
fn neg_mod(a: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    if a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 {
        [0u64; 4]
    } else {
        sub_mod(modulus, a, modulus)
    }
}

// ---------------------------------------------------------------------------
// Convert [u64; 4] to/from little-endian bytes at runtime
// ---------------------------------------------------------------------------

#[inline(always)]
fn limbs_to_bytes(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 4 {
        let bytes = limbs[i].to_le_bytes();
        let base = i * 8;
        let mut j = 0;
        while j < 8 {
            out[base + j] = bytes[j];
            j += 1;
        }
        i += 1;
    }
    out
}

#[inline(always)]
fn bytes_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        let base = i * 8;
        let mut buf = [0u8; 8];
        let mut j = 0;
        while j < 8 {
            buf[j] = bytes[base + j];
            j += 1;
        }
        limbs[i] = u64::from_le_bytes(buf);
        i += 1;
    }
    limbs
}

// ---------------------------------------------------------------------------
// hcf() — halt-and-catch-fire, makes the proof unsatisfiable
// ---------------------------------------------------------------------------

/// Spoils the proof on error.  On RISC-V guest, emits a branch instruction that
/// the verifier cannot satisfy; on host, panics.
#[cfg(all(
    not(feature = "host"),
    any(target_arch = "riscv32", target_arch = "riscv64")
))]
#[inline(always)]
pub fn hcf() {
    unsafe {
        let u = 0u64;
        let v = 1u64;
        core::arch::asm!(
            ".insn b {opcode}, {funct3}, {rs1}, {rs2}, . + 2",
            opcode = const 0x5B,
            funct3 = const 0b001,
            rs1 = in(reg) u,
            rs2 = in(reg) v,
            options(nostack)
        );
    }
}
#[cfg(all(
    not(feature = "host"),
    not(any(target_arch = "riscv32", target_arch = "riscv64"))
))]
pub fn hcf() {
    panic!("hcf called on non-RISC-V target without host feature");
}
#[cfg(feature = "host")]
pub fn hcf() {
    panic!("explicit host code panic function called");
}

// ---------------------------------------------------------------------------
// UnwrapOrSpoilProof trait
// ---------------------------------------------------------------------------

/// A trait for unwrapping Results in a way that spoils the proof on error.
///
/// # When to Use
///
/// Use `.unwrap_or_spoil_proof()` when you want to **assert** that a condition holds,
/// and if it doesn't, **no valid proof should exist**. This is appropriate when:
///
/// - You want to prove "X is valid" (not "I checked X")
/// - A malicious prover should not be able to produce any proof if the condition fails
/// - The error case represents something that should be cryptographically impossible
///
/// # When NOT to Use
///
/// Do NOT use `.unwrap_or_spoil_proof()` for:
///
/// - Input validation (use `.unwrap()` or return `Result` instead)
/// - Expected error cases that should be handled gracefully
/// - Cases where you want a valid proof showing the error occurred
///
/// # Example
///
/// ```ignore
/// // Soft verification - returns Result, proof is valid either way
/// let result = ecdsa_verify(z, r, s, q);
///
/// // Normal panic - proof is valid, shows program panicked
/// ecdsa_verify(z, r, s, q).unwrap();
///
/// // Spoil proof - NO valid proof can exist if signature is invalid
/// ecdsa_verify(z, r, s, q).unwrap_or_spoil_proof();
/// ```
pub trait UnwrapOrSpoilProof<T> {
    /// Unwraps the Result, returning the success value.
    ///
    /// If the Result is `Err`, this function triggers a halt-and-catch-fire (HCF)
    /// instruction that makes the proof unsatisfiable. No valid proof can be
    /// generated for an execution that reaches this error path.
    ///
    /// # Returns
    /// The unwrapped `Ok` value if successful.
    ///
    /// # Proof Implications
    /// - `Ok(v)` -> Returns `v`, proof proceeds normally
    /// - `Err(_)` -> Proof becomes unsatisfiable (cannot be verified)
    fn unwrap_or_spoil_proof(self) -> T;
}

impl<T> UnwrapOrSpoilProof<T> for Result<T, P256Error> {
    #[inline(always)]
    fn unwrap_or_spoil_proof(self) -> T {
        match self {
            Ok(v) => v,
            Err(_) => {
                hcf();
                // hcf() spoils the proof; panic to satisfy the type checker
                panic!("unwrap_or_spoil_proof failed")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// P256Error
// ---------------------------------------------------------------------------

/// Error types for P-256 operations
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum P256Error {
    InvalidFqElement, // input array does not correspond to a valid Fq element
    InvalidFrElement, // input array does not correspond to a valid Fr element
    NotOnCurve,       // point is not on the P-256 curve
    QAtInfinity,      // public key is point at infinity
    ROrSZero,         // one of the signature components is zero
    RxMismatch,       // computed R.x does not match r
}

// ===========================================================================
// P256Fq — base field element (NOT Montgomery form)
// ===========================================================================

/// P-256 base field element.
/// Wraps `[u64; 4]` in standard (non-Montgomery) form.
/// Addition, subtraction, negation, doubling, and tripling are pure integer
/// arithmetic.  Multiplication, squaring, and division dispatch to custom
/// RISC-V inline instructions on guest, or `num_bigint::BigUint` on host.
#[derive(Clone, PartialEq, Debug)]
pub struct P256Fq {
    e: [u64; 4],
}

impl P256Fq {
    /// Creates a new P256Fq element from a `[u64; 4]` array.
    /// Returns `Err(P256Error::InvalidFqElement)` if the value >= p.
    #[inline(always)]
    pub fn from_u64_arr(arr: &[u64; 4]) -> Result<Self, P256Error> {
        if is_fq_non_canonical(arr) {
            return Err(P256Error::InvalidFqElement);
        }
        Ok(P256Fq { e: *arr })
    }

    /// Creates a new P256Fq element from a `[u64; 4]` array (unchecked).
    /// The array is assumed to contain a value in the range `[0, p)`.
    #[inline(always)]
    pub fn from_u64_arr_unchecked(arr: &[u64; 4]) -> Self {
        P256Fq { e: *arr }
    }

    /// Returns the four u64 limbs (little-endian).
    #[inline(always)]
    pub fn e(&self) -> [u64; 4] {
        self.e
    }

    /// Returns the element as 32 little-endian bytes.
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        limbs_to_bytes(&self.e)
    }

    /// Creates a P256Fq from 32 little-endian bytes.
    /// Returns error if the value >= p.
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, P256Error> {
        let limbs = bytes_to_limbs(bytes);
        Self::from_u64_arr(&limbs)
    }

    /// Constructs from a BigUint (host only).
    #[cfg(feature = "host")]
    pub fn from_biguint(n: &BigUint) -> Self {
        P256Fq {
            e: biguint_to_limbs(n),
        }
    }

    /// Returns the additive identity element (0).
    #[inline(always)]
    pub fn zero() -> Self {
        P256Fq { e: [0u64; 4] }
    }

    /// Returns true if the element is zero.
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.e == [0u64; 4]
    }

    /// Returns `-self mod p`.
    #[inline(always)]
    pub fn neg(&self) -> Self {
        P256Fq {
            e: neg_mod(&self.e, &P256_MODULUS),
        }
    }

    /// Returns `self + other mod p`.
    #[inline(always)]
    pub fn add(&self, other: &P256Fq) -> Self {
        P256Fq {
            e: add_mod(&self.e, &other.e, &P256_MODULUS),
        }
    }

    /// Returns `self - other mod p`.
    #[inline(always)]
    pub fn sub(&self, other: &P256Fq) -> Self {
        P256Fq {
            e: sub_mod(&self.e, &other.e, &P256_MODULUS),
        }
    }

    /// Returns `2 * self mod p`.
    #[inline(always)]
    pub fn dbl(&self) -> Self {
        self.add(self)
    }

    /// Returns `3 * self mod p`.
    #[inline(always)]
    pub fn tpl(&self) -> Self {
        self.dbl().add(self)
    }

    // -----------------------------------------------------------------------
    // mul — RISC-V guest (inline instruction)
    // -----------------------------------------------------------------------

    /// Returns `self * other mod p`.
    /// Uses a custom RISC-V inline instruction for performance.
    #[cfg(all(
        not(feature = "host"),
        any(target_arch = "riscv32", target_arch = "riscv64")
    ))]
    #[inline(always)]
    pub fn mul(&self, other: &P256Fq) -> Self {
        let mut e = [0u64; 4];
        unsafe {
            use crate::{INLINE_OPCODE, P256_FUNCT7, P256_MULQ_FUNCT3};
            core::arch::asm!(
                ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
                opcode = const INLINE_OPCODE,
                funct3 = const P256_MULQ_FUNCT3,
                funct7 = const P256_FUNCT7,
                rd = in(reg) e.as_mut_ptr(),
                rs1 = in(reg) self.e.as_ptr(),
                rs2 = in(reg) other.e.as_ptr(),
                options(nostack)
            );
        }
        if is_fq_non_canonical(&e) {
            hcf();
        }
        P256Fq::from_u64_arr_unchecked(&e[0..4].try_into().unwrap())
    }

    /// Panics on non-RISC-V guest (no inline available).
    #[cfg(all(
        not(feature = "host"),
        not(any(target_arch = "riscv32", target_arch = "riscv64"))
    ))]
    pub fn mul(&self, _other: &P256Fq) -> Self {
        panic!("P256Fq::mul called on non-RISC-V target without host feature");
    }

    /// Host implementation using `num_bigint::BigUint`.
    #[cfg(feature = "host")]
    #[inline(always)]
    pub fn mul(&self, other: &P256Fq) -> Self {
        let a = BigUint::from_bytes_le(&self.to_bytes());
        let b = BigUint::from_bytes_le(&other.to_bytes());
        let q = BigUint::from_bytes_le(&P256_MODULUS_BYTES);
        let result = (a * b) % q;
        P256Fq::from_biguint(&result)
    }

    // -----------------------------------------------------------------------
    // square — RISC-V guest (inline instruction)
    // -----------------------------------------------------------------------

    /// Returns `self^2 mod p`.
    /// Uses a custom RISC-V inline instruction for performance.
    #[cfg(all(
        not(feature = "host"),
        any(target_arch = "riscv32", target_arch = "riscv64")
    ))]
    #[inline(always)]
    pub fn square(&self) -> Self {
        let mut e = [0u64; 4];
        unsafe {
            use crate::{INLINE_OPCODE, P256_FUNCT7, P256_SQUAREQ_FUNCT3};
            core::arch::asm!(
                ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, x0",
                opcode = const INLINE_OPCODE,
                funct3 = const P256_SQUAREQ_FUNCT3,
                funct7 = const P256_FUNCT7,
                rd = in(reg) e.as_mut_ptr(),
                rs1 = in(reg) self.e.as_ptr(),
                options(nostack)
            );
        }
        if is_fq_non_canonical(&e) {
            hcf();
        }
        P256Fq::from_u64_arr_unchecked(&e[0..4].try_into().unwrap())
    }

    /// Panics on non-RISC-V guest (no inline available).
    #[cfg(all(
        not(feature = "host"),
        not(any(target_arch = "riscv32", target_arch = "riscv64"))
    ))]
    pub fn square(&self) -> Self {
        panic!("P256Fq::square called on non-RISC-V target without host feature");
    }

    /// Host implementation using `num_bigint::BigUint`.
    #[cfg(feature = "host")]
    #[inline(always)]
    pub fn square(&self) -> Self {
        let a = BigUint::from_bytes_le(&self.to_bytes());
        let q = BigUint::from_bytes_le(&P256_MODULUS_BYTES);
        let result = (&a * &a) % q;
        P256Fq::from_biguint(&result)
    }

    // -----------------------------------------------------------------------
    // div / div_assume_nonzero — RISC-V guest (inline instruction)
    // -----------------------------------------------------------------------

    /// Returns `self / other mod p`.  Assumes `other != 0`.
    /// Uses a custom RISC-V inline instruction for performance.
    #[cfg(all(
        not(feature = "host"),
        any(target_arch = "riscv32", target_arch = "riscv64")
    ))]
    #[inline(always)]
    fn div_assume_nonzero(&self, other: &P256Fq) -> Self {
        let mut e = [0u64; 4];
        unsafe {
            use crate::{INLINE_OPCODE, P256_DIVQ_FUNCT3, P256_FUNCT7};
            core::arch::asm!(
                ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
                opcode = const INLINE_OPCODE,
                funct3 = const P256_DIVQ_FUNCT3,
                funct7 = const P256_FUNCT7,
                rd = in(reg) e.as_mut_ptr(),
                rs1 = in(reg) self.e.as_ptr(),
                rs2 = in(reg) other.e.as_ptr(),
                options(nostack)
            );
        }
        if is_fq_non_canonical(&e) {
            hcf();
        }
        P256Fq::from_u64_arr_unchecked(&e[0..4].try_into().unwrap())
    }

    /// Returns `self / other mod p`.
    /// Spoils the proof if `other == 0`.
    #[cfg(all(
        not(feature = "host"),
        any(target_arch = "riscv32", target_arch = "riscv64")
    ))]
    #[inline(always)]
    pub fn div(&self, other: &P256Fq) -> Self {
        // spoil proof if other == 0
        if other.is_zero() {
            hcf();
        }
        self.div_assume_nonzero(other)
    }

    /// Panics on non-RISC-V guest (no inline available).
    #[cfg(all(
        not(feature = "host"),
        not(any(target_arch = "riscv32", target_arch = "riscv64"))
    ))]
    pub fn div_assume_nonzero(&self, _other: &P256Fq) -> Self {
        panic!("P256Fq::div_assume_nonzero called on non-RISC-V target without host feature");
    }

    /// Panics on non-RISC-V guest (no inline available).
    #[cfg(all(
        not(feature = "host"),
        not(any(target_arch = "riscv32", target_arch = "riscv64"))
    ))]
    pub fn div(&self, _other: &P256Fq) -> Self {
        panic!("P256Fq::div called on non-RISC-V target without host feature");
    }

    /// Host implementation: assumes `other != 0`.
    /// Computes modular inverse via `other^(p-2) mod p`, then multiplies.
    #[cfg(feature = "host")]
    #[inline(always)]
    pub fn div_assume_nonzero(&self, other: &P256Fq) -> Self {
        let a = BigUint::from_bytes_le(&self.to_bytes());
        let b = BigUint::from_bytes_le(&other.to_bytes());
        let q = BigUint::from_bytes_le(&P256_MODULUS_BYTES);
        // b^(p-2) mod p  (Fermat's little theorem)
        let two = BigUint::from(2u32);
        let exp = &q - &two;
        let b_inv = b.modpow(&exp, &q);
        let result = (a * b_inv) % &q;
        P256Fq::from_biguint(&result)
    }

    /// Host implementation: checks `other != 0` then delegates.
    #[cfg(feature = "host")]
    #[inline(always)]
    pub fn div(&self, other: &P256Fq) -> Self {
        if other.is_zero() {
            panic!("division by zero in P256Fq::div");
        }
        self.div_assume_nonzero(other)
    }
}

// ===========================================================================
// P256Fr — scalar field element (NOT Montgomery form)
// ===========================================================================

/// P-256 scalar field element.
/// Wraps `[u64; 4]` in standard (non-Montgomery) form.
/// Same dispatch strategy as `P256Fq` but using the scalar field order `n`
/// and the MULR/SQUARER/DIVR funct3 values.
#[derive(Clone, PartialEq, Debug)]
pub struct P256Fr {
    e: [u64; 4],
}

impl P256Fr {
    /// Creates a new P256Fr element from a `[u64; 4]` array.
    /// Returns `Err(P256Error::InvalidFrElement)` if the value >= n.
    #[inline(always)]
    pub fn from_u64_arr(arr: &[u64; 4]) -> Result<Self, P256Error> {
        if is_fr_non_canonical(arr) {
            return Err(P256Error::InvalidFrElement);
        }
        Ok(P256Fr { e: *arr })
    }

    /// Creates a new P256Fr element from a `[u64; 4]` array (unchecked).
    /// The array is assumed to contain a value in the range `[0, n)`.
    #[inline(always)]
    pub fn from_u64_arr_unchecked(arr: &[u64; 4]) -> Self {
        P256Fr { e: *arr }
    }

    /// Returns the four u64 limbs (little-endian).
    #[inline(always)]
    pub fn e(&self) -> [u64; 4] {
        self.e
    }

    /// Returns the element as 32 little-endian bytes.
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        limbs_to_bytes(&self.e)
    }

    /// Creates a P256Fr from 32 little-endian bytes.
    /// Returns error if the value >= n.
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, P256Error> {
        let limbs = bytes_to_limbs(bytes);
        Self::from_u64_arr(&limbs)
    }

    /// Constructs from a BigUint (host only).
    #[cfg(feature = "host")]
    pub fn from_biguint(n: &BigUint) -> Self {
        P256Fr {
            e: biguint_to_limbs(n),
        }
    }

    /// Returns the additive identity element (0).
    #[inline(always)]
    pub fn zero() -> Self {
        P256Fr { e: [0u64; 4] }
    }

    /// Returns true if the element is zero.
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.e == [0u64; 4]
    }

    /// Returns `-self mod n`.
    #[inline(always)]
    pub fn neg(&self) -> Self {
        P256Fr {
            e: neg_mod(&self.e, &P256_ORDER),
        }
    }

    /// Returns `self + other mod n`.
    #[inline(always)]
    pub fn add(&self, other: &P256Fr) -> Self {
        P256Fr {
            e: add_mod(&self.e, &other.e, &P256_ORDER),
        }
    }

    /// Returns `self - other mod n`.
    #[inline(always)]
    pub fn sub(&self, other: &P256Fr) -> Self {
        P256Fr {
            e: sub_mod(&self.e, &other.e, &P256_ORDER),
        }
    }

    /// Returns `2 * self mod n`.
    #[inline(always)]
    pub fn dbl(&self) -> Self {
        self.add(self)
    }

    /// Returns `3 * self mod n`.
    #[inline(always)]
    pub fn tpl(&self) -> Self {
        self.dbl().add(self)
    }

    // -----------------------------------------------------------------------
    // mul — RISC-V guest (inline instruction)
    // -----------------------------------------------------------------------

    /// Returns `self * other mod n`.
    /// Uses a custom RISC-V inline instruction for performance.
    #[cfg(all(
        not(feature = "host"),
        any(target_arch = "riscv32", target_arch = "riscv64")
    ))]
    #[inline(always)]
    pub fn mul(&self, other: &P256Fr) -> Self {
        let mut e = [0u64; 4];
        unsafe {
            use crate::{INLINE_OPCODE, P256_FUNCT7, P256_MULR_FUNCT3};
            core::arch::asm!(
                ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
                opcode = const INLINE_OPCODE,
                funct3 = const P256_MULR_FUNCT3,
                funct7 = const P256_FUNCT7,
                rd = in(reg) e.as_mut_ptr(),
                rs1 = in(reg) self.e.as_ptr(),
                rs2 = in(reg) other.e.as_ptr(),
                options(nostack)
            );
        }
        if is_fr_non_canonical(&e) {
            hcf();
        }
        P256Fr::from_u64_arr_unchecked(&e[0..4].try_into().unwrap())
    }

    /// Panics on non-RISC-V guest (no inline available).
    #[cfg(all(
        not(feature = "host"),
        not(any(target_arch = "riscv32", target_arch = "riscv64"))
    ))]
    pub fn mul(&self, _other: &P256Fr) -> Self {
        panic!("P256Fr::mul called on non-RISC-V target without host feature");
    }

    /// Host implementation using `num_bigint::BigUint`.
    #[cfg(feature = "host")]
    #[inline(always)]
    pub fn mul(&self, other: &P256Fr) -> Self {
        let a = BigUint::from_bytes_le(&self.to_bytes());
        let b = BigUint::from_bytes_le(&other.to_bytes());
        let n = BigUint::from_bytes_le(&P256_ORDER_BYTES);
        let result = (a * b) % n;
        P256Fr::from_biguint(&result)
    }

    // -----------------------------------------------------------------------
    // square — RISC-V guest (inline instruction)
    // -----------------------------------------------------------------------

    /// Returns `self^2 mod n`.
    /// Uses a custom RISC-V inline instruction for performance.
    #[cfg(all(
        not(feature = "host"),
        any(target_arch = "riscv32", target_arch = "riscv64")
    ))]
    #[inline(always)]
    pub fn square(&self) -> Self {
        let mut e = [0u64; 4];
        unsafe {
            use crate::{INLINE_OPCODE, P256_FUNCT7, P256_SQUARER_FUNCT3};
            core::arch::asm!(
                ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, x0",
                opcode = const INLINE_OPCODE,
                funct3 = const P256_SQUARER_FUNCT3,
                funct7 = const P256_FUNCT7,
                rd = in(reg) e.as_mut_ptr(),
                rs1 = in(reg) self.e.as_ptr(),
                options(nostack)
            );
        }
        if is_fr_non_canonical(&e) {
            hcf();
        }
        P256Fr::from_u64_arr_unchecked(&e[0..4].try_into().unwrap())
    }

    /// Panics on non-RISC-V guest (no inline available).
    #[cfg(all(
        not(feature = "host"),
        not(any(target_arch = "riscv32", target_arch = "riscv64"))
    ))]
    pub fn square(&self) -> Self {
        panic!("P256Fr::square called on non-RISC-V target without host feature");
    }

    /// Host implementation using `num_bigint::BigUint`.
    #[cfg(feature = "host")]
    #[inline(always)]
    pub fn square(&self) -> Self {
        let a = BigUint::from_bytes_le(&self.to_bytes());
        let n = BigUint::from_bytes_le(&P256_ORDER_BYTES);
        let result = (&a * &a) % n;
        P256Fr::from_biguint(&result)
    }

    // -----------------------------------------------------------------------
    // div / div_assume_nonzero — RISC-V guest (inline instruction)
    // -----------------------------------------------------------------------

    /// Returns `self / other mod n`.  Assumes `other != 0`.
    /// Uses a custom RISC-V inline instruction for performance.
    #[cfg(all(
        not(feature = "host"),
        any(target_arch = "riscv32", target_arch = "riscv64")
    ))]
    #[inline(always)]
    fn div_assume_nonzero(&self, other: &P256Fr) -> Self {
        let mut e = [0u64; 4];
        unsafe {
            use crate::{INLINE_OPCODE, P256_DIVR_FUNCT3, P256_FUNCT7};
            core::arch::asm!(
                ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
                opcode = const INLINE_OPCODE,
                funct3 = const P256_DIVR_FUNCT3,
                funct7 = const P256_FUNCT7,
                rd = in(reg) e.as_mut_ptr(),
                rs1 = in(reg) self.e.as_ptr(),
                rs2 = in(reg) other.e.as_ptr(),
                options(nostack)
            );
        }
        if is_fr_non_canonical(&e) {
            hcf();
        }
        P256Fr::from_u64_arr_unchecked(&e[0..4].try_into().unwrap())
    }

    /// Returns `self / other mod n`.
    /// Spoils the proof if `other == 0`.
    #[cfg(all(
        not(feature = "host"),
        any(target_arch = "riscv32", target_arch = "riscv64")
    ))]
    #[inline(always)]
    pub fn div(&self, other: &P256Fr) -> Self {
        // spoil proof if other == 0
        if other.is_zero() {
            hcf();
        }
        self.div_assume_nonzero(other)
    }

    /// Panics on non-RISC-V guest (no inline available).
    #[cfg(all(
        not(feature = "host"),
        not(any(target_arch = "riscv32", target_arch = "riscv64"))
    ))]
    pub fn div_assume_nonzero(&self, _other: &P256Fr) -> Self {
        panic!("P256Fr::div_assume_nonzero called on non-RISC-V target without host feature");
    }

    /// Panics on non-RISC-V guest (no inline available).
    #[cfg(all(
        not(feature = "host"),
        not(any(target_arch = "riscv32", target_arch = "riscv64"))
    ))]
    pub fn div(&self, _other: &P256Fr) -> Self {
        panic!("P256Fr::div called on non-RISC-V target without host feature");
    }

    /// Host implementation: assumes `other != 0`.
    /// Computes modular inverse via `other^(n-2) mod n`, then multiplies.
    #[cfg(feature = "host")]
    #[inline(always)]
    pub fn div_assume_nonzero(&self, other: &P256Fr) -> Self {
        let a = BigUint::from_bytes_le(&self.to_bytes());
        let b = BigUint::from_bytes_le(&other.to_bytes());
        let n = BigUint::from_bytes_le(&P256_ORDER_BYTES);
        // b^(n-2) mod n  (Fermat's little theorem)
        let two = BigUint::from(2u32);
        let exp = &n - &two;
        let b_inv = b.modpow(&exp, &n);
        let result = (a * b_inv) % &n;
        P256Fr::from_biguint(&result)
    }

    /// Host implementation: checks `other != 0` then delegates.
    #[cfg(feature = "host")]
    #[inline(always)]
    pub fn div(&self, other: &P256Fr) -> Self {
        if other.is_zero() {
            panic!("division by zero in P256Fr::div");
        }
        self.div_assume_nonzero(other)
    }
}

// === P256Point and ECDSA ===

/// P-256 point in affine form
/// Infinity is represented as (0, 0) since this point is not on the curve
#[derive(Clone, PartialEq, Debug)]
pub struct P256Point {
    x: P256Fq,
    y: P256Fq,
}

impl P256Point {
    #[inline(always)]
    pub fn new(x: P256Fq, y: P256Fq) -> Result<Self, P256Error> {
        let p = P256Point { x, y };
        if p.is_on_curve() { Ok(p) } else { Err(P256Error::NotOnCurve) }
    }
    #[inline(always)]
    pub fn new_unchecked(x: P256Fq, y: P256Fq) -> Self { P256Point { x, y } }
    #[inline(always)]
    pub fn to_u64_arr(&self) -> [u64; 8] {
        let mut arr = [0u64; 8];
        arr[0..4].copy_from_slice(&self.x.e());
        arr[4..8].copy_from_slice(&self.y.e());
        arr
    }
    #[inline(always)]
    pub fn from_u64_arr(arr: &[u64; 8]) -> Result<Self, P256Error> {
        let x = P256Fq::from_u64_arr(&[arr[0], arr[1], arr[2], arr[3]])?;
        let y = P256Fq::from_u64_arr(&[arr[4], arr[5], arr[6], arr[7]])?;
        P256Point::new(x, y)
    }
    #[inline(always)]
    pub fn from_u64_arr_unchecked(arr: &[u64; 8]) -> Self {
        let x = P256Fq::from_u64_arr_unchecked(&[arr[0], arr[1], arr[2], arr[3]]);
        let y = P256Fq::from_u64_arr_unchecked(&[arr[4], arr[5], arr[6], arr[7]]);
        P256Point { x, y }
    }
    #[inline(always)]
    pub fn x(&self) -> P256Fq { self.x.clone() }
    #[inline(always)]
    pub fn y(&self) -> P256Fq { self.y.clone() }
    #[inline(always)]
    pub fn generator() -> Self {
        P256Point {
            x: P256Fq::from_u64_arr_unchecked(&crate::P256_GENERATOR_X),
            y: P256Fq::from_u64_arr_unchecked(&crate::P256_GENERATOR_Y),
        }
    }
    #[inline(always)]
    pub fn infinity() -> Self { P256Point { x: P256Fq::zero(), y: P256Fq::zero() } }
    #[inline(always)]
    pub fn is_infinity(&self) -> bool { self.x.is_zero() && self.y.is_zero() }

    /// Check if point is on P-256 curve: y^2 = x^3 + ax + b, a = -3
    #[inline(always)]
    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity() { return true; }
        // a = p - 3
        let a = P256Fq::from_u64_arr_unchecked(&[
            0xFFFF_FFFF_FFFF_FFFC, 0x0000_0000_FFFF_FFFF,
            0x0000_0000_0000_0000, 0xFFFF_FFFF_0000_0001,
        ]);
        let b = P256Fq::from_u64_arr_unchecked(&crate::P256_CURVE_B);
        let y2 = self.y.square();
        let x3 = self.x.square().mul(&self.x);
        let ax = a.mul(&self.x);
        y2 == x3.add(&ax).add(&b)
    }

    #[inline(always)]
    pub fn neg(&self) -> Self {
        if self.is_infinity() { P256Point::infinity() }
        else { P256Point { x: self.x.clone(), y: self.y.neg() } }
    }

    /// Point doubling: s = (3x^2 + a) / (2y) where a = p-3
    #[inline(always)]
    pub fn double(&self) -> Self {
        if self.y.is_zero() { return P256Point::infinity(); }
        let a = P256Fq::from_u64_arr_unchecked(&[
            0xFFFF_FFFF_FFFF_FFFC, 0x0000_0000_FFFF_FFFF,
            0x0000_0000_0000_0000, 0xFFFF_FFFF_0000_0001,
        ]);
        let x2 = self.x.square();
        let s = x2.tpl().add(&a).div_assume_nonzero(&self.y.dbl());
        let x3 = s.square().sub(&self.x.dbl());
        let y3 = s.mul(&self.x.sub(&x3)).sub(&self.y);
        P256Point { x: x3, y: y3 }
    }

    /// Point addition
    #[inline(always)]
    pub fn add(&self, other: &P256Point) -> Self {
        if self.is_infinity() { return other.clone(); }
        if other.is_infinity() { return self.clone(); }
        if self.x == other.x && self.y == other.y { return self.double(); }
        if self.x == other.x { return P256Point::infinity(); }
        let s = self.y.sub(&other.y).div_assume_nonzero(&self.x.sub(&other.x));
        let x3 = s.square().sub(&self.x.add(&other.x));
        let y3 = s.mul(&self.x.sub(&x3)).sub(&self.y);
        P256Point { x: x3, y: y3 }
    }

    /// Optimized 2P+Q (saves one division per Shamir iteration)
    #[inline(always)]
    pub fn double_and_add(&self, other: &P256Point) -> Self {
        if self.is_infinity() { return other.clone(); }
        if other.is_infinity() { return self.add(self); }
        if self.x == other.x && self.y == other.y { return self.add(self).add(other); }
        if self.x == other.x && self.y != other.y { return self.clone(); }
        let ns = self.y.sub(&other.y).div_assume_nonzero(&other.x.sub(&self.x));
        let nx2 = other.x.sub(&ns.square());
        let t = self.y.dbl().div_assume_nonzero(&self.x.dbl().add(&nx2)).add(&ns);
        let x3 = t.square().add(&nx2);
        let y3 = t.mul(&self.x.sub(&x3)).sub(&self.y);
        P256Point { x: x3, y: y3 }
    }
}

// ============================================================================
// ECDSA P-256 verification
// ============================================================================

/// 2x256-bit Shamir's trick: u1*G + u2*Q
#[inline(always)]
fn p256_shamir(u1: P256Fr, u2: P256Fr, q: P256Point) -> P256Point {
    let g = P256Point::generator();
    let gq = g.add(&q);
    let table = [P256Point::infinity(), g.clone(), q.clone(), gq];

    let mut res = P256Point::infinity();
    for bit in (0..256).rev() {
        let b1 = (u1.e()[bit / 64] >> (bit % 64)) & 1;
        let b2 = (u2.e()[bit / 64] >> (bit % 64)) & 1;
        let idx = (b1 + 2 * b2) as usize;

        if res.is_infinity() {
            if idx != 0 { res = table[idx].clone(); }
        } else if idx != 0 {
            res = res.double_and_add(&table[idx]);
        } else {
            res = res.double();
        }
    }
    res
}

/// Verify an ECDSA P-256 signature.
/// z = message hash, r/s = signature, q = public key point.
#[inline(always)]
pub fn ecdsa_verify(
    z: P256Fr, r: P256Fr, s: P256Fr, q: P256Point,
) -> Result<(), P256Error> {
    if q.is_infinity() { return Err(P256Error::QAtInfinity); }
    if r.is_zero() || s.is_zero() { return Err(P256Error::ROrSZero); }

    let u1 = z.div_assume_nonzero(&s);
    let u2 = r.div_assume_nonzero(&s);

    let r_claim = p256_shamir(u1, u2, q);

    if r_claim.is_infinity() { return Err(P256Error::RxMismatch); }

    // R.x mod n: single conditional subtraction since p < 2n
    let mut rx = r_claim.x;
    if is_fr_non_canonical(&rx.e()) {
        rx = rx.sub(&P256Fq::from_u64_arr_unchecked(&crate::P256_ORDER));
    }
    if rx.e() != r.e() { return Err(P256Error::RxMismatch); }
    Ok(())
}
