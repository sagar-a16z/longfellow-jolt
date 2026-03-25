// P-256 ECDSA verification optimized for Jolt zkVM.
//
// Uses BIGINT256_MUL inline for field multiplication (hardware-accelerated),
// with P-256 modular reduction ported from longfellow-zk's fp_p256.h.
//
// Architecture mirrors jolt-inlines-secp256k1/src/sdk.rs but adapted for
// the NIST P-256 curve (a = -3, different prime structure, no GLV).

extern crate alloc;
use alloc::vec::Vec;

// P-256 base field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1
pub const P: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

// P-256 curve order n
pub const N: [u64; 4] = [
    0xF3B9CAC2FC632551,
    0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
];

// P-256 curve parameter b
pub const B: [u64; 4] = [
    0x3BCE3C3E27D2604B,
    0x651D06B0CC53B0F6,
    0xB3EBBD55769886BC,
    0x5AC635D8AA3A93E7,
];

// P-256 generator x
pub const GX: [u64; 4] = [
    0xF4A13945D898C296,
    0x77037D812DEB33A0,
    0xF8BCE6E563A440F2,
    0x6B17D1F2E12C4247,
];

// P-256 generator y
pub const GY: [u64; 4] = [
    0xCBB6406837BF51F5,
    0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16,
    0x4FE342E2FE1A7F9B,
];

// ============================================================================
// Field element (Fp) — base field of P-256, NOT Montgomery form
// Uses BIGINT256_MUL inline + Barrett-like reduction
// ============================================================================

#[derive(Clone, PartialEq, Debug)]
pub struct Fp {
    pub e: [u64; 4],
}

impl Fp {
    #[inline(always)]
    pub fn zero() -> Self { Fp { e: [0; 4] } }

    #[inline(always)]
    pub fn one() -> Self { Fp { e: [1, 0, 0, 0] } }

    #[inline(always)]
    pub fn is_zero(&self) -> bool { self.e == [0; 4] }

    #[inline(always)]
    pub fn from_limbs(e: [u64; 4]) -> Self { Fp { e } }

    // Addition mod p
    #[inline(always)]
    pub fn add(&self, other: &Fp) -> Fp {
        let mut r = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s1, c1) = self.e[i].overflowing_add(other.e[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            r[i] = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry > 0 {
            // Result = r + 2^256. Since both inputs < p < 2^256,
            // sum < 2p < 2^257, so result - p < 2^256.
            // Compute r + (2^256 - p) = r + (2^224 - 2^192 - 2^96 + 1)
            // This is equivalent to subtracting p from the 257-bit value.
            sub_borrow(&mut r, &P);
            // Since sum < 2p, this always produces a non-negative result.
        } else if gte(&r, &P) {
            sub_borrow(&mut r, &P);
        }
        Fp { e: r }
    }

    // Subtraction mod p
    #[inline(always)]
    pub fn sub(&self, other: &Fp) -> Fp {
        self.sub_inner(other)
    }

    #[inline(always)]
    fn sub_inner(&self, other: &Fp) -> Fp {
        let mut r = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (s1, b1) = self.e[i].overflowing_sub(other.e[i]);
            let (s2, b2) = s1.overflowing_sub(borrow);
            r[i] = s2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        if borrow > 0 {
            // Add p back
            let mut carry = 0u64;
            for i in 0..4 {
                let (s1, c1) = r[i].overflowing_add(P[i]);
                let (s2, c2) = s1.overflowing_add(carry);
                r[i] = s2;
                carry = (c1 as u64) + (c2 as u64);
            }
        }
        Fp { e: r }
    }

    // Double
    #[inline(always)]
    pub fn dbl(&self) -> Fp { self.add(self) }

    // Negation mod p
    #[inline(always)]
    pub fn neg(&self) -> Fp {
        if self.is_zero() { return Fp::zero(); }
        Fp { e: P }.sub_inner(self)
    }

    // Multiplication mod p using BIGINT256_MUL inline + P-256 Barrett reduction
    #[inline(always)]
    pub fn mul(&self, other: &Fp) -> Fp {
        let wide = bigint256_mul(self.e, other.e);
        reduce_p256(&wide)
    }

    // Squaring
    #[inline(always)]
    pub fn square(&self) -> Fp { self.mul(self) }

    // Inversion via Fermat's little theorem: a^(p-2) mod p
    // Uses a square-and-multiply chain optimized for P-256
    pub fn inv(&self) -> Fp {
        // p-2 = 2^256 - 2^224 + 2^192 + 2^96 - 3
        // Use repeated squaring. For P-256, there's an efficient addition chain.
        // We use a simple but correct approach: binary method on p-2
        let mut result = Fp::one();
        let mut base = self.clone();

        // p - 2 in little-endian limbs
        let exp: [u64; 4] = [
            0xFFFFFFFFFFFFFFFD, // -3 in the low limb
            0x00000000FFFFFFFF,
            0x0000000000000000,
            0xFFFFFFFF00000001,
        ];

        for i in 0..4 {
            let mut word = exp[i];
            for _ in 0..64 {
                if word & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.square();
                word >>= 1;
            }
        }
        result
    }

    // Division: a / b = a * b^(-1)
    #[inline(always)]
    pub fn div(&self, other: &Fp) -> Fp {
        self.mul(&other.inv())
    }
}

// ============================================================================
// Scalar field element (Fn) — order of P-256
// ============================================================================

#[derive(Clone, PartialEq, Debug)]
pub struct Fn {
    pub e: [u64; 4],
}

impl Fn {
    #[inline(always)]
    pub fn zero() -> Self { Fn { e: [0; 4] } }

    #[inline(always)]
    pub fn is_zero(&self) -> bool { self.e == [0; 4] }

    #[inline(always)]
    pub fn from_limbs(e: [u64; 4]) -> Self { Fn { e } }

    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut e = [0u64; 4];
        for i in 0..4 {
            let off = (3 - i) * 8;
            e[i] = u64::from_be_bytes([
                bytes[off], bytes[off+1], bytes[off+2], bytes[off+3],
                bytes[off+4], bytes[off+5], bytes[off+6], bytes[off+7],
            ]);
        }
        Fn { e }
    }

    // Multiplication mod n using BIGINT256_MUL + two-pass reduction
    #[inline(always)]
    pub fn mul(&self, other: &Fn) -> Fn {
        let r256n: [u64; 4] = [0x0C46353D039CDAAF, 0x4319055258E8617B, 0, 0x00000000FFFFFFFF];

        let mut w = [0u64; 8];
        let wide = bigint256_mul(self.e, other.e);
        for i in 0..8 { w[i] = wide[i]; }

        // Loop until high part is zero (r256n is 97 bits, ~3 iterations)
        loop {
            let high = [w[4], w[5], w[6], w[7]];
            if high == [0, 0, 0, 0] { break; }

            let hr = bigint256_mul(high, r256n);
            w[4] = 0; w[5] = 0; w[6] = 0; w[7] = 0;
            let mut carry = 0u64;
            for i in 0..8 {
                let (s1, c1) = w[i].overflowing_add(hr[i]);
                let (s2, c2) = s1.overflowing_add(carry);
                w[i] = s2;
                carry = (c1 as u64) + (c2 as u64);
            }
        }

        let mut result = [w[0], w[1], w[2], w[3]];
        while gte(&result, &N) {
            sub_borrow(&mut result, &N);
        }
        Fn { e: result }
    }

    // Inversion mod n via Fermat
    pub fn inv(&self) -> Fn {
        let mut result = Fn { e: [1, 0, 0, 0] };
        let mut base = self.clone();
        let exp: [u64; 4] = [
            N[0].wrapping_sub(2), N[1], N[2], N[3],
        ];
        for i in 0..4 {
            let mut word = exp[i];
            for _ in 0..64 {
                if word & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.mul(&base);
                word >>= 1;
            }
        }
        result
    }

    // Addition mod n
    #[inline(always)]
    pub fn add(&self, other: &Fn) -> Fn {
        let mut r = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s1, c1) = self.e[i].overflowing_add(other.e[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            r[i] = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry > 0 {
            sub_borrow(&mut r, &N);
        } else if gte(&r, &N) {
            sub_borrow(&mut r, &N);
        }
        Fn { e: r }
    }

    pub fn sub(&self, other: &Fn) -> Fn {
        let mut r = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (s1, b1) = self.e[i].overflowing_sub(other.e[i]);
            let (s2, b2) = s1.overflowing_sub(borrow);
            r[i] = s2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        if borrow > 0 {
            let mut carry = 0u64;
            for i in 0..4 {
                let (s1, c1) = r[i].overflowing_add(N[i]);
                let (s2, c2) = s1.overflowing_add(carry);
                r[i] = s2;
                carry = (c1 as u64) + (c2 as u64);
            }
        }
        Fn { e: r }
    }
}

// ============================================================================
// BIGINT256_MUL: 256x256 -> 512 bit multiplication (Jolt inline)
// ============================================================================

#[inline(always)]
pub fn bigint256_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    jolt_inlines_bigint::bigint256_mul(a, b)
}

// ============================================================================
// P-256 modular reduction (ported from longfellow-zk fp_p256.h)
//
// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
// Uses NIST FIPS 186-4 fast reduction for the P-256 prime
// ============================================================================

pub fn reduce_p256(wide: &[u64; 8]) -> Fp {
    // Reduce 512-bit product mod P-256 prime.
    // r256p is 224 bits wide, so each pass only removes 32 bits.
    // We loop until the high part is zero (~8 iterations).
    // This function runs during compute_advice (not proved), so cost is fine.

    let r256p: [u64; 4] = [1, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFE];

    let mut w = [0u64; 8];
    for i in 0..8 { w[i] = wide[i]; }

    loop {
        let high = [w[4], w[5], w[6], w[7]];
        if high == [0, 0, 0, 0] { break; }

        let hr = bigint256_mul(high, r256p);
        w[4] = 0; w[5] = 0; w[6] = 0; w[7] = 0;
        let mut carry = 0u64;
        for i in 0..8 {
            let (s1, c1) = w[i].overflowing_add(hr[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            w[i] = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
    }

    let mut result = [w[0], w[1], w[2], w[3]];
    while gte(&result, &P) {
        sub_borrow(&mut result, &P);
    }
    Fp { e: result }
}

#[inline(always)]
fn widening_mul(a: u64, b: u64) -> (u64, u64) {
    let r = (a as u128) * (b as u128);
    (r as u64, (r >> 64) as u64)
}

fn add_p(r: &mut [u64; 4]) {
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = r[i].overflowing_add(P[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        r[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
}

// Reduction mod n for the scalar field.
// Uses the identity: 2^256 ≡ r256n (mod n) where r256n = 2^256 - n is small.
// Processes high limbs individually with widening_mul to avoid calling bigint256_mul.
pub fn reduce_mod_n(wide: &[u64; 8]) -> Fn {
    // 2^256 mod n
    let r256n: [u64; 4] = [0x0C46353D039CDAAF, 0x4319055258E8617B, 0, 0x00000000FFFFFFFF];

    // Start with low 256 bits. Use 8 accumulators to handle all shifts.
    let mut acc = [0u128; 8];
    for i in 0..4 { acc[i] = wide[i] as u128; }

    // For each high limb, add wide[i] * r256n
    for i in 4..8 {
        if wide[i] == 0 { continue; }
        let w = wide[i] as u128;
        let shift = i - 4;
        for j in 0..4 {
            acc[shift + j] += w * (r256n[j] as u128);
        }
    }

    // Carry propagation through 64-bit boundaries
    for i in 0..7 {
        acc[i+1] += acc[i] >> 64;
        acc[i] &= 0xFFFFFFFFFFFFFFFF;
    }

    // Second reduction: acc[4..7] * 2^256 ≡ acc[4..7] * r256n (mod n)
    // r256n has at most 97 bits, and acc[4..7] are small, so product fits easily
    if acc[4] != 0 || acc[5] != 0 || acc[6] != 0 || acc[7] != 0 {
        let mut acc2 = [0u128; 8];
        for i in 0..4 { acc2[i] = acc[i]; }
        for i in 4..8 {
            if acc[i] == 0 { continue; }
            let w = acc[i];
            let shift = i - 4;
            for j in 0..4 {
                acc2[shift + j] += w * (r256n[j] as u128);
            }
        }
        for i in 0..7 {
            acc2[i+1] += acc2[i] >> 64;
            acc2[i] &= 0xFFFFFFFFFFFFFFFF;
        }
        for i in 0..8 { acc[i] = acc2[i]; }

        // Third pass (extremely rare, acc[4..7] should be near zero now)
        if acc[4] != 0 || acc[5] != 0 || acc[6] != 0 || acc[7] != 0 {
            let mut acc3 = [0u128; 8];
            for i in 0..4 { acc3[i] = acc[i]; }
            for i in 4..8 {
                if acc[i] == 0 { continue; }
                let w = acc[i];
                let shift = i - 4;
                for j in 0..4 {
                    acc3[shift + j] += w * (r256n[j] as u128);
                }
            }
            for i in 0..7 {
                acc3[i+1] += acc3[i] >> 64;
                acc3[i] &= 0xFFFFFFFFFFFFFFFF;
            }
            for i in 0..8 { acc[i] = acc3[i]; }
        }
    }

    let mut r = [acc[0] as u64, acc[1] as u64, acc[2] as u64, acc[3] as u64];
    while gte(&r, &N) {
        sub_borrow(&mut r, &N);
    }
    Fn { e: r }
}

// ============================================================================
// Utility
// ============================================================================

#[inline(always)]
pub fn gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] { return true; }
        if a[i] < b[i] { return false; }
    }
    true // equal
}

pub fn sub_borrow(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (s1, b1) = a[i].overflowing_sub(b[i]);
        let (s2, b2) = s1.overflowing_sub(borrow);
        a[i] = s2;
        borrow = (b1 as u64) + (b2 as u64);
    }
}

// ============================================================================
// P-256 Point (affine coordinates)
// Infinity = (0, 0) since this point is not on the curve
// ============================================================================

#[derive(Clone, PartialEq, Debug)]
pub struct Point {
    pub x: Fp,
    pub y: Fp,
}

impl Point {
    #[inline(always)]
    pub fn infinity() -> Self { Point { x: Fp::zero(), y: Fp::zero() } }

    #[inline(always)]
    pub fn is_infinity(&self) -> bool { self.x.is_zero() && self.y.is_zero() }

    #[inline(always)]
    pub fn generator() -> Self { Point { x: Fp { e: GX }, y: Fp { e: GY } } }

    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity() { return true; }
        // y^2 = x^3 + a*x + b where a = -3
        let y2 = self.y.square();
        let x3 = self.x.square().mul(&self.x);
        let ax = self.x.mul(&Fp { e: P }.sub_inner(&Fp { e: [3, 0, 0, 0] })); // a = p - 3
        let rhs = x3.add(&ax).add(&Fp { e: B });
        y2 == rhs
    }

    #[inline(always)]
    pub fn neg(&self) -> Self {
        if self.is_infinity() { return Point::infinity(); }
        Point { x: self.x.clone(), y: self.y.neg() }
    }

    // Point doubling: s = (3*x^2 + a) / (2*y), a = -3
    #[inline(always)]
    pub fn double(&self) -> Self {
        if self.y.is_zero() { return Point::infinity(); }
        let x2 = self.x.square();
        let three_x2 = x2.add(&x2).add(&x2);
        // a = -3 = p - 3
        let a = Fp { e: P }.sub_inner(&Fp { e: [3, 0, 0, 0] });
        let num = three_x2.add(&a);
        let den = self.y.dbl();
        let s = num.mul(&den.inv());
        let x3 = s.square().sub(&self.x.dbl());
        let y3 = s.mul(&self.x.sub(&x3)).sub(&self.y);
        Point { x: x3, y: y3 }
    }

    // Point addition
    #[inline(always)]
    pub fn add(&self, other: &Point) -> Self {
        if self.is_infinity() { return other.clone(); }
        if other.is_infinity() { return self.clone(); }
        if self.x == other.x && self.y == other.y { return self.double(); }
        if self.x == other.x { return Point::infinity(); }

        let dx = other.x.sub(&self.x);
        let dy = other.y.sub(&self.y);
        let s = dy.mul(&dx.inv());
        let x3 = s.square().sub(&self.x).sub(&other.x);
        let y3 = s.mul(&self.x.sub(&x3)).sub(&self.y);
        Point { x: x3, y: y3 }
    }
}

// ============================================================================
// ECDSA P-256 verification using Shamir's trick
//
// Ported from longfellow-zk's verify_witness.h triple-scalar-mult approach
// and the secp256k1 inline's ecdsa_verify pattern.
// ============================================================================

/// Verify ECDSA P-256 signature.
/// digest: 32-byte SHA-256 hash (big-endian)
/// sig_r, sig_s: 32-byte signature components (big-endian)
/// pk_x, pk_y: 32-byte public key coordinates (big-endian)
pub fn ecdsa_verify_p256(
    pk_x: &[u8; 32], pk_y: &[u8; 32],
    sig_r: &[u8; 32], sig_s: &[u8; 32],
    digest: &[u8; 32],
) -> bool {
    let r = Fn::from_be_bytes(sig_r);
    let s = Fn::from_be_bytes(sig_s);
    let z = Fn::from_be_bytes(digest);

    if r.is_zero() || s.is_zero() { return false; }

    // u1 = z * s^(-1) mod n
    let s_inv = s.inv();
    let u1 = z.mul(&s_inv);
    let u2 = r.mul(&s_inv);

    // R = u1*G + u2*Q using Shamir's trick (simultaneous double-and-add)
    let q = Point {
        x: Fp { e: be_bytes_to_limbs(pk_x) },
        y: Fp { e: be_bytes_to_limbs(pk_y) },
    };

    if !q.is_on_curve() { return false; }

    // Precompute: [0, G, Q, G+Q]
    let g = Point::generator();
    let gq = g.add(&q);
    let table = [Point::infinity(), g.clone(), q.clone(), gq];

    // Shamir's trick: scan bits from MSB to LSB
    let mut acc = Point::infinity();
    for bit in (0..256).rev() {
        acc = acc.double();
        let b1 = get_bit(&u1.e, bit);
        let b2 = get_bit(&u2.e, bit);
        let idx = b1 + 2 * b2;
        if idx != 0 {
            acc = acc.add(&table[idx]);
        }
    }

    if acc.is_infinity() { return false; }

    // Check: R.x mod n == r
    let rx = acc.x;
    let mut rx_mod_n = rx.e;
    if gte(&rx_mod_n, &N) {
        sub_borrow(&mut rx_mod_n, &N);
    }
    rx_mod_n == r.e
}

pub fn be_bytes_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut e = [0u64; 4];
    for i in 0..4 {
        let off = (3 - i) * 8;
        e[i] = u64::from_be_bytes([
            bytes[off], bytes[off+1], bytes[off+2], bytes[off+3],
            bytes[off+4], bytes[off+5], bytes[off+6], bytes[off+7],
        ]);
    }
    e
}

fn get_bit(limbs: &[u64; 4], bit: usize) -> usize {
    let word = bit / 64;
    let pos = bit % 64;
    ((limbs[word] >> pos) & 1) as usize
}
