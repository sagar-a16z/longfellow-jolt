// P-256 field arithmetic using Jolt's advice mechanism.
//
// Prover supplies field operation results; guest verifies algebraic relations.
// This mirrors the secp256k1 inline's approach but uses the advice tape.

use super::p256_fast::{Fp, Fn, P, N, bigint256_mul, gte, sub_borrow, Point, be_bytes_to_limbs};

// ============================================================================
// Fp multiplication via advice: verify a*b == q*p + c
// ============================================================================

#[cfg(feature = "compute_advice")]
pub fn fp_mul_advice(a: &Fp, b: &Fp) -> Fp {
    let wide = bigint256_mul(a.e, b.e);
    // Use Fp::mul to get c (ensures same reduction as guest-side)
    let c = a.mul(b);
    let q = compute_quotient(&wide, &c.e, &P);
    let mut w = jolt::AdviceWriter::get();
    for &limb in &c.e { w.write_u64(limb); }
    for &limb in &q { w.write_u64(limb); }
    c
}

#[cfg(not(feature = "compute_advice"))]
pub fn fp_mul_advice(a: &Fp, b: &Fp) -> Fp {
    let mut r = jolt::AdviceReader::get();
    let c = [r.read_u64(), r.read_u64(), r.read_u64(), r.read_u64()];
    let q = [r.read_u64(), r.read_u64(), r.read_u64(), r.read_u64()];
    assert!(!gte(&c, &P), "advice: c >= p");
    let ab = bigint256_mul(a.e, b.e);
    let qp = bigint256_mul(q, P);
    let expected = add_wide(&qp, &c);
    assert!(ab == expected, "advice: a*b != q*p + c");
    Fp { e: c }
}

// ============================================================================
// Fp inversion via advice: verify a * inv == 1
// ============================================================================

#[cfg(feature = "compute_advice")]
pub fn fp_inv_advice(a: &Fp) -> Fp {
    let inv = a.inv();
    let mut w = jolt::AdviceWriter::get();
    // Write the inverse (4 u64s)
    for &limb in &inv.e { w.write_u64(limb); }
    // The proving pass calls fp_mul_advice(a, &inv) which reads 8 more u64s.
    // Use Fp::mul to compute c (same reduction as proving pass).
    let wide = bigint256_mul(a.e, inv.e);
    let c = a.mul(&inv);
    let q = compute_quotient(&wide, &c.e, &P);
    for &limb in &c.e { w.write_u64(limb); }
    for &limb in &q { w.write_u64(limb); }
    inv
}

#[cfg(not(feature = "compute_advice"))]
pub fn fp_inv_advice(a: &Fp) -> Fp {
    let mut r = jolt::AdviceReader::get();
    let inv_e = [r.read_u64(), r.read_u64(), r.read_u64(), r.read_u64()];
    assert!(!gte(&inv_e, &P), "advice: inv >= p");
    let inv = Fp { e: inv_e };
    let product = fp_mul_advice(a, &inv);
    assert!(product == Fp::one(), "advice: a * inv != 1");
    inv
}

// ============================================================================
// Fn multiplication via advice
// ============================================================================

#[cfg(feature = "compute_advice")]
pub fn fn_mul_advice(a: &Fn, b: &Fn) -> Fn {
    // Use the same bigint256_mul that the proving pass will use
    let wide = bigint256_mul(a.e, b.e);
    // Use Fn's own mul method to get c (ensures same reduction as Fn::mul)
    let c = a.mul(b);
    let q = compute_quotient(&wide, &c.e, &N);
    let mut w = jolt::AdviceWriter::get();
    for &limb in &c.e { w.write_u64(limb); }
    for &limb in &q { w.write_u64(limb); }
    c
}

#[cfg(not(feature = "compute_advice"))]
pub fn fn_mul_advice(a: &Fn, b: &Fn) -> Fn {
    let mut r = jolt::AdviceReader::get();
    let c = [r.read_u64(), r.read_u64(), r.read_u64(), r.read_u64()];
    let q = [r.read_u64(), r.read_u64(), r.read_u64(), r.read_u64()];
    assert!(!gte(&c, &N), "advice: c >= n");
    let ab = bigint256_mul(a.e, b.e);
    let qn = bigint256_mul(q, N);
    let expected = add_wide(&qn, &c);
    assert!(ab == expected, "advice: a*b != q*n + c");
    Fn { e: c }
}

// ============================================================================
// Fn inversion via advice
// ============================================================================

#[cfg(feature = "compute_advice")]
pub fn fn_inv_advice(a: &Fn) -> Fn {
    let inv = a.inv();
    let mut w = jolt::AdviceWriter::get();
    // Write the inverse (4 u64s)
    for &limb in &inv.e { w.write_u64(limb); }
    // The proving pass calls fn_mul_advice(a, &inv) which reads 8 more u64s.
    // Use Fn::mul to compute c (same reduction as proving pass).
    let wide = bigint256_mul(a.e, inv.e);
    let c = a.mul(&inv);
    let q = compute_quotient(&wide, &c.e, &N);
    for &limb in &c.e { w.write_u64(limb); }
    for &limb in &q { w.write_u64(limb); }
    inv
}

#[cfg(not(feature = "compute_advice"))]
pub fn fn_inv_advice(a: &Fn) -> Fn {
    let mut r = jolt::AdviceReader::get();
    let inv_e = [r.read_u64(), r.read_u64(), r.read_u64(), r.read_u64()];
    assert!(!gte(&inv_e, &N), "advice: inv >= n");
    let inv = Fn { e: inv_e };
    let product = fn_mul_advice(a, &inv);
    assert!(product.e == [1, 0, 0, 0], "advice: a * inv != 1 mod n");
    inv
}

// ============================================================================
// Helpers
// ============================================================================

/// 512-bit addition: wide + small (small has 4 limbs, padded to 8)
fn add_wide(wide: &[u64; 8], small: &[u64; 4]) -> [u64; 8] {
    let mut result = [0u64; 8];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = wide[i].overflowing_add(small[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        result[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
    for i in 4..8 {
        let (s1, c1) = wide[i].overflowing_add(carry);
        result[i] = s1;
        carry = c1 as u64;
    }
    result
}

/// Compute quotient q = (wide - c) / modulus. Only runs during compute_advice.
#[cfg(feature = "compute_advice")]
fn compute_quotient(wide: &[u64; 8], c: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    // wide - c
    let mut diff = [0u64; 8];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (s1, b1) = wide[i].overflowing_sub(c[i]);
        let (s2, b2) = s1.overflowing_sub(borrow);
        diff[i] = s2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    for i in 4..8 {
        let (s1, b1) = wide[i].overflowing_sub(borrow);
        diff[i] = s1;
        borrow = b1 as u64;
    }
    // Verify by multiplication: q * modulus should equal diff
    // Use trial: diff / modulus using simple shift-and-subtract
    div_512_by_256(&diff, modulus)
}

/// 512 / 256 -> 256 quotient using shift-and-subtract.
#[cfg(feature = "compute_advice")]
fn div_512_by_256(num: &[u64; 8], den: &[u64; 4]) -> [u64; 4] {
    // Convert to u128 for easier arithmetic (only in compute_advice, not proved)
    let mut n = [0u128; 8];
    for i in 0..8 { n[i] = num[i] as u128; }

    // Reconstruct as big number and divide
    // Simple approach: repeated subtraction with binary search on quotient bits
    let mut quotient = [0u64; 4];
    let mut remainder = [0u64; 9];
    for i in 0..8 { remainder[i] = num[i]; }

    for bit in (0..256).rev() {
        let word = bit / 64;
        let pos = bit % 64;

        // Check if we can subtract den << bit from remainder
        // This is equivalent to checking remainder >= den * 2^bit
        let can_sub = can_subtract_shifted(&remainder, den, word, pos);

        if can_sub {
            subtract_shifted(&mut remainder, den, word, pos);
            quotient[word] |= 1u64 << pos;
        }
    }
    quotient
}

#[cfg(feature = "compute_advice")]
fn can_subtract_shifted(rem: &[u64; 9], den: &[u64; 4], word_shift: usize, bit_shift: usize) -> bool {
    // Check if rem >= den << (word_shift * 64 + bit_shift)
    // Compare from MSB down
    for i in (0..9).rev() {
        let den_val = shifted_limb(den, i, word_shift, bit_shift);
        if rem[i] > den_val { return true; }
        if rem[i] < den_val { return false; }
    }
    true // equal
}

#[cfg(feature = "compute_advice")]
fn subtract_shifted(rem: &mut [u64; 9], den: &[u64; 4], word_shift: usize, bit_shift: usize) {
    let mut borrow = 0u64;
    for i in 0..9 {
        let den_val = shifted_limb(den, i, word_shift, bit_shift);
        let (s1, b1) = rem[i].overflowing_sub(den_val);
        let (s2, b2) = s1.overflowing_sub(borrow);
        rem[i] = s2;
        borrow = (b1 as u64) + (b2 as u64);
    }
}

#[cfg(feature = "compute_advice")]
fn shifted_limb(den: &[u64; 4], limb_idx: usize, word_shift: usize, bit_shift: usize) -> u64 {
    if limb_idx < word_shift { return 0; }
    let src = limb_idx - word_shift;
    if bit_shift == 0 {
        if src < 4 { den[src] } else { 0 }
    } else {
        let lo = if src < 4 { den[src] << bit_shift } else { 0 };
        let hi = if src > 0 && src - 1 < 4 { den[src - 1] >> (64 - bit_shift) } else { 0 };
        lo | hi
    }
}

// ============================================================================
// ECDSA verification using advice-based field operations
// ============================================================================

fn point_double_adv(p: &Point) -> Point {
    if p.y.is_zero() { return Point::infinity(); }
    let a_coeff = Fp { e: P }.sub(&Fp { e: [3, 0, 0, 0] });
    let x2 = fp_mul_advice(&p.x, &p.x);
    let three_x2 = x2.add(&x2).add(&x2);
    let num = three_x2.add(&a_coeff);
    let den_inv = fp_inv_advice(&p.y.dbl());
    let s = fp_mul_advice(&num, &den_inv);
    let x3 = fp_mul_advice(&s, &s).sub(&p.x.dbl());
    let y3 = fp_mul_advice(&s, &p.x.sub(&x3)).sub(&p.y);
    Point { x: x3, y: y3 }
}

fn point_add_adv(p: &Point, q: &Point) -> Point {
    if p.x.is_zero() && p.y.is_zero() { return q.clone(); }
    if q.x.is_zero() && q.y.is_zero() { return p.clone(); }
    if p.x == q.x && p.y == q.y { return point_double_adv(p); }
    if p.x == q.x { return Point::infinity(); }

    let dx = q.x.sub(&p.x);
    let dy = q.y.sub(&p.y);
    let dx_inv = fp_inv_advice(&dx);
    let s = fp_mul_advice(&dy, &dx_inv);
    let x3 = fp_mul_advice(&s, &s).sub(&p.x).sub(&q.x);
    let y3 = fp_mul_advice(&s, &p.x.sub(&x3)).sub(&p.y);
    Point { x: x3, y: y3 }
}

pub fn ecdsa_verify_p256_advice(
    pk_x: &[u8; 32], pk_y: &[u8; 32],
    sig_r: &[u8; 32], sig_s: &[u8; 32],
    digest: &[u8; 32],
) -> bool {
    let r = Fn::from_be_bytes(sig_r);
    let s = Fn::from_be_bytes(sig_s);
    let z = Fn::from_be_bytes(digest);

    if r.is_zero() || s.is_zero() { return false; }

    let s_inv = fn_inv_advice(&s);
    let u1 = fn_mul_advice(&z, &s_inv);
    let u2 = fn_mul_advice(&r, &s_inv);

    let g = Point::generator();
    let q = Point {
        x: Fp { e: be_bytes_to_limbs(pk_x) },
        y: Fp { e: be_bytes_to_limbs(pk_y) },
    };

    let gq = point_add_adv(&g, &q);
    let table = [Point::infinity(), g.clone(), q.clone(), gq];

    let get_bit = |limbs: &[u64; 4], bit: usize| -> usize {
        ((limbs[bit / 64] >> (bit % 64)) & 1) as usize
    };

    let mut acc = Point::infinity();
    for bit in (0..256).rev() {
        acc = point_double_adv(&acc);
        let b1 = get_bit(&u1.e, bit);
        let b2 = get_bit(&u2.e, bit);
        let idx = b1 + 2 * b2;
        if idx != 0 {
            acc = point_add_adv(&acc, &table[idx]);
        }
    }

    if acc.x.is_zero() && acc.y.is_zero() { return false; }

    let mut rx = acc.x.e;
    if gte(&rx, &N) {
        sub_borrow(&mut rx, &N);
    }
    rx == r.e
}
