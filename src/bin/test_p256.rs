// Test harness for p256_fast field arithmetic.
// Runs on the host to compare our custom implementation against the p256 crate.

extern crate jolt_inlines_bigint;

// Pull in the guest's p256_fast module by re-implementing the key types here
// for host-side testing. The bigint256_mul has a host fallback.

fn main() {
    test_field_basics();
    test_field_mul();
    test_field_inv();
    test_point_on_curve();
    test_point_add();
    test_ecdsa();
    println!("\nAll tests passed!");
}

// ---- Inline the p256_fast types for host testing ----
// (Can't import from guest directly due to Jolt macro complications)

const P: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF,
    0x0000000000000000, 0xFFFFFFFF00000001,
];

const N: [u64; 4] = [
    0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000,
];

const GX: [u64; 4] = [
    0xF4A13945D898C296, 0x77037D812DEB33A0,
    0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247,
];
const GY: [u64; 4] = [
    0xCBB6406837BF51F5, 0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B,
];
const B: [u64; 4] = [
    0x3BCE3C3E27D2604B, 0x651D06B0CC53B0F6,
    0xB3EBBD55769886BC, 0x5AC635D8AA3A93E7,
];

#[derive(Clone, PartialEq, Debug)]
struct Fp { e: [u64; 4] }

impl Fp {
    fn zero() -> Self { Fp { e: [0; 4] } }
    fn one() -> Self { Fp { e: [1, 0, 0, 0] } }
    fn is_zero(&self) -> bool { self.e == [0; 4] }

    fn add(&self, other: &Fp) -> Fp {
        let mut r = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s1, c1) = self.e[i].overflowing_add(other.e[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            r[i] = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry > 0 {
            sub_borrow(&mut r, &P);
        } else if gte(&r, &P) {
            sub_borrow(&mut r, &P);
        }
        Fp { e: r }
    }

    fn sub(&self, other: &Fp) -> Fp { self.sub_inner(other) }

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

    fn dbl(&self) -> Fp { self.add(self) }
    fn neg(&self) -> Fp {
        if self.is_zero() { return Fp::zero(); }
        Fp { e: P }.sub_inner(self)
    }

    fn mul(&self, other: &Fp) -> Fp {
        let wide = jolt_inlines_bigint::bigint256_mul(self.e, other.e);
        reduce_p256_v3(&wide)
    }

    fn square(&self) -> Fp { self.mul(self) }

    fn inv(&self) -> Fp {
        let mut result = Fp::one();
        let mut base = self.clone();
        let exp: [u64; 4] = [
            0xFFFFFFFFFFFFFFFD, 0x00000000FFFFFFFF,
            0x0000000000000000, 0xFFFFFFFF00000001,
        ];
        for i in 0..4 {
            let mut word = exp[i];
            for _ in 0..64 {
                if word & 1 == 1 { result = result.mul(&base); }
                base = base.square();
                word >>= 1;
            }
        }
        result
    }

    fn div(&self, other: &Fp) -> Fp { self.mul(&other.inv()) }
}

fn widening_mul(a: u64, b: u64) -> (u64, u64) {
    let r = (a as u128) * (b as u128);
    (r as u64, (r >> 64) as u64)
}

fn reduce_p256_v3(wide: &[u64; 8]) -> Fp {
    let c = |i: usize| -> i128 { ((wide[i / 2] >> (32 * (i & 1))) & 0xFFFFFFFF) as i128 };
    let mut t = [0i128; 8];
    for i in 0..8 { t[i] = c(i); }
    t[3]+=2*c(11); t[4]+=2*c(12); t[5]+=2*c(13); t[6]+=2*c(14); t[7]+=2*c(15);
    t[3]+=2*c(12); t[4]+=2*c(13); t[5]+=2*c(14); t[6]+=2*c(15);
    t[0]+=c(8); t[1]+=c(9); t[2]+=c(10); t[6]+=c(14); t[7]+=c(15);
    t[0]+=c(9); t[1]+=c(10); t[2]+=c(11); t[3]+=c(13); t[4]+=c(14); t[5]+=c(15); t[6]+=c(13); t[7]+=c(8);
    t[0]-=c(11); t[1]-=c(12); t[2]-=c(13); t[6]-=c(8); t[7]-=c(10);
    t[0]-=c(12); t[1]-=c(13); t[2]-=c(14); t[3]-=c(15); t[6]-=c(9); t[7]-=c(11);
    t[0]-=c(13); t[1]-=c(14); t[2]-=c(15); t[3]-=c(8); t[4]-=c(9); t[5]-=c(10); t[7]-=c(12);
    t[0]-=c(14); t[1]-=c(15); t[3]-=c(9); t[4]-=c(10); t[5]-=c(11); t[7]-=c(13);

    for i in 0..7 { let carry = t[i] >> 32; t[i] -= carry << 32; t[i+1] += carry; }
    let top = t[7] >> 32;
    t[7] -= top << 32;

    let mut r = [0u64; 4];
    for i in 0..4 { r[i] = (t[2*i] as u64) | ((t[2*i+1] as u64) << 32); }

    if top > 0 { for _ in 0..top { sub_borrow(&mut r, &P); } }
    else if top < 0 { for _ in 0..(-top) { add_to(&mut r, &P); } }
    while gte(&r, &P) { sub_borrow(&mut r, &P); }
    Fp { e: r }
}

fn reduce_p256_v2(wide: &[u64; 8]) -> Fp {
    let c = |i: usize| -> u64 { (wide[i / 2] >> (32 * (i & 1))) & 0xFFFFFFFF };
    let mk = |w0: u64, w1: u64, w2: u64, w3: u64, w4: u64, w5: u64, w6: u64, w7: u64| -> [u64; 4] {
        [w0 | (w1 << 32), w2 | (w3 << 32), w4 | (w5 << 32), w6 | (w7 << 32)]
    };

    let a  = mk(c(0),  c(1),  c(2),  c(3),  c(4),  c(5),  c(6),  c(7));
    let s1 = mk(0,     0,     0,     c(11), c(12), c(13), c(14), c(15));
    let s2 = mk(0,     0,     0,     c(12), c(13), c(14), c(15), 0   );
    let s3 = mk(c(8),  c(9),  c(10), 0,     0,     0,     c(14), c(15));
    let s4 = mk(c(9),  c(10), c(11), c(13), c(14), c(15), c(13), c(8));
    let d1 = mk(c(11), c(12), c(13), 0,     0,     0,     c(8),  c(10));
    let d2 = mk(c(12), c(13), c(14), c(15), 0,     0,     c(9),  c(11));
    let d3 = mk(c(13), c(14), c(15), c(8),  c(9),  c(10), 0,     c(12));
    let d4 = mk(c(14), c(15), 0,     c(9),  c(10), c(11), 0,     c(13));

    let mut result = Fp { e: a };
    result = result.add(&Fp { e: s1 }); result = result.add(&Fp { e: s1 });
    result = result.add(&Fp { e: s2 }); result = result.add(&Fp { e: s2 });
    result = result.add(&Fp { e: s3 }); result = result.add(&Fp { e: s4 });
    result = result.sub(&Fp { e: d1 }); result = result.sub(&Fp { e: d2 });
    result = result.sub(&Fp { e: d3 }); result = result.sub(&Fp { e: d4 });
    result
}

#[allow(dead_code)]
fn reduce_p256(wide: &[u64; 8]) -> Fp {
    let mut acc = [0u64; 5];
    acc[0] = wide[0]; acc[1] = wide[1]; acc[2] = wide[2]; acc[3] = wide[3];

    let r256: [u64; 4] = [1, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFE];

    let high: [u64; 4] = [wide[4], wide[5], wide[6], wide[7]];
    let product = jolt_inlines_bigint::bigint256_mul(high, r256);

    let mut carry = 0u64;
    for j in 0..4 {
        let (s1, c1) = acc[j].overflowing_add(product[j]);
        let (s2, c2) = s1.overflowing_add(carry);
        acc[j] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
    acc[4] = carry;

    let high2: [u64; 4] = [product[4], product[5], product[6], product[7]];
    if high2 != [0; 4] {
        let product2 = jolt_inlines_bigint::bigint256_mul(high2, r256);
        let mut carry2 = 0u64;
        for j in 0..4 {
            let (s1, c1) = acc[j].overflowing_add(product2[j]);
            let (s2, c2) = s1.overflowing_add(carry2);
            acc[j] = s2;
            carry2 = (c1 as u64) + (c2 as u64);
        }
        acc[4] = acc[4].wrapping_add(carry2).wrapping_add(product2[4]);
    }

    while acc[4] > 0 {
        let overflow = acc[4];
        acc[4] = 0;
        let mut carry3 = 0u64;
        for j in 0..4 {
            let (lo, hi) = widening_mul(overflow, r256[j]);
            let (s1, c1) = acc[j].overflowing_add(lo);
            let (s2, c2) = s1.overflowing_add(carry3);
            acc[j] = s2;
            carry3 = hi + (c1 as u64) + (c2 as u64);
        }
        acc[4] = carry3;
    }

    let mut result = [acc[0], acc[1], acc[2], acc[3]];
    while gte(&result, &P) {
        sub_borrow(&mut result, &P);
    }
    Fp { e: result }
}

fn gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] { return true; }
        if a[i] < b[i] { return false; }
    }
    true
}

fn sub_borrow(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (s1, b1) = a[i].overflowing_sub(b[i]);
        let (s2, b2) = s1.overflowing_sub(borrow);
        a[i] = s2;
        borrow = (b1 as u64) + (b2 as u64);
    }
}

// ---- Reference using p256 crate ----

fn p256_field_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    use p256::FieldBytes;
    use p256::elliptic_curve::ops::Reduce;
    use p256::U256;

    // Convert limbs to big-endian bytes
    let a_bytes = limbs_to_be(a);
    let b_bytes = limbs_to_be(b);

    let a_val = U256::from_be_slice(&a_bytes);
    let b_val = U256::from_be_slice(&b_bytes);

    // Use the p256 scalar field for multiplication mod p
    // Actually we need the base field. Let's use a different approach.
    // Multiply as big integers and reduce.
    let wide = jolt_inlines_bigint::bigint256_mul(*a, *b);

    // Reference: compute mod p using u128 arithmetic
    reduce_reference(&wide)
}

fn reduce_reference(wide: &[u64; 8]) -> [u64; 4] {
    // Compute wide mod p using the python-style big integer approach
    let mut val = [0u128; 8];
    for i in 0..8 { val[i] = wide[i] as u128; }

    // Reconstruct as a single big number, reduce mod p
    // p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    // Use the NIST reduction with 32-bit limbs

    let mut c = [0u64; 16]; // 32-bit values stored in u64
    for i in 0..8 {
        c[2*i] = wide[i] & 0xFFFFFFFF;
        c[2*i+1] = wide[i] >> 32;
    }

    // NIST FIPS 186-4 reduction for P-256
    // s1 = (c15,c14,c13,c12,c11, 0, 0, 0)
    // s2 = ( 0,c15,c14,c13,c12, 0, 0, 0)
    // s3 = (c15,c14, 0, 0, 0,c10,c9,c8)
    // s4 = (c8,c13,c15,c14,c13,c11,c10,c9)
    // d1 = (c10,c8, 0, 0, 0,c13,c12,c11)
    // d2 = (c11,c9, 0, 0,c15,c14,c13,c12)
    // d3 = (c12, 0,c10,c9,c8,c15,c14,c13)
    // d4 = (c13, 0,c11,c10,c9, 0,c15,c14)
    // result = a + 2*s1 + 2*s2 + s3 + s4 - d1 - d2 - d3 - d4 mod p

    let mut t = [0i128; 8];
    // a
    for i in 0..8 { t[i] = c[i] as i128; }
    // +2*s1
    t[3] += 2*(c[11] as i128); t[4] += 2*(c[12] as i128); t[5] += 2*(c[13] as i128); t[6] += 2*(c[14] as i128); t[7] += 2*(c[15] as i128);
    // +2*s2
    t[3] += 2*(c[12] as i128); t[4] += 2*(c[13] as i128); t[5] += 2*(c[14] as i128); t[6] += 2*(c[15] as i128);
    // +s3
    t[0] += c[8] as i128; t[1] += c[9] as i128; t[2] += c[10] as i128; t[6] += c[14] as i128; t[7] += c[15] as i128;
    // +s4
    t[0] += c[9] as i128; t[1] += c[10] as i128; t[2] += c[11] as i128; t[3] += c[13] as i128; t[4] += c[14] as i128; t[5] += c[15] as i128; t[6] += c[13] as i128; t[7] += c[8] as i128;
    // -d1
    t[0] -= c[11] as i128; t[1] -= c[12] as i128; t[2] -= c[13] as i128; t[6] -= c[8] as i128; t[7] -= c[10] as i128;
    // -d2
    t[0] -= c[12] as i128; t[1] -= c[13] as i128; t[2] -= c[14] as i128; t[3] -= c[15] as i128; t[6] -= c[9] as i128; t[7] -= c[11] as i128;
    // -d3
    t[0] -= c[13] as i128; t[1] -= c[14] as i128; t[2] -= c[15] as i128; t[3] -= c[8] as i128; t[4] -= c[9] as i128; t[5] -= c[10] as i128; t[7] -= c[12] as i128;
    // -d4
    t[0] -= c[14] as i128; t[1] -= c[15] as i128; t[3] -= c[9] as i128; t[4] -= c[10] as i128; t[5] -= c[11] as i128; t[7] -= c[13] as i128;

    // Carry propagation (signed)
    for i in 0..7 {
        let carry = if t[i] >= 0 { t[i] >> 32 } else { -(((-t[i] + 0xFFFFFFFF) >> 32)) };
        t[i+1] += carry;
        t[i] -= carry << 32;
    }

    // Convert to u64 limbs, handling negative values by adding p
    let mut r = [0u64; 4];
    for i in 0..4 {
        let lo = t[2*i];
        let hi = t[2*i+1];
        r[i] = ((lo as u64) & 0xFFFFFFFF) | (((hi as u64) & 0xFFFFFFFF) << 32);
    }

    // Add p while negative, subtract p while >= p
    let top = t[7] >> 32;
    if top < 0 {
        for _ in 0..(-top) {
            add_to(&mut r, &P);
        }
    }
    while gte(&r, &P) {
        sub_borrow(&mut r, &P);
    }
    r
}

fn add_to(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        a[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
}

fn limbs_to_be(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let bytes = limbs[3-i].to_be_bytes();
        out[i*8..(i+1)*8].copy_from_slice(&bytes);
    }
    out
}

// ---- Tests ----

fn test_field_basics() {
    print!("test_field_basics... ");
    let one = Fp::one();
    let zero = Fp::zero();

    // 0 + 1 = 1
    assert_eq!(zero.add(&one), one);
    // 1 - 1 = 0
    assert_eq!(one.sub(&one), zero);
    // 1 + (p-1) = 0 (mod p)
    let pm1 = Fp { e: [P[0]-1, P[1], P[2], P[3]] };
    assert_eq!(one.add(&pm1), zero);

    println!("OK");
}

fn test_field_mul() {
    print!("test_field_mul... ");
    let one = Fp::one();
    let two = Fp { e: [2, 0, 0, 0] };
    let three = Fp { e: [3, 0, 0, 0] };

    // 1 * 1 = 1
    assert_eq!(one.mul(&one), one, "1*1 failed");
    // 2 * 3 = 6
    let six = Fp { e: [6, 0, 0, 0] };
    let result = two.mul(&three);
    assert_eq!(result, six, "2*3 failed: got {:?}", result.e);

    // Test against reference
    let a = Fp { e: [0x1234567890abcdef, 0xfedcba9876543210, 0x1111111111111111, 0x2222222222222222] };
    let b = Fp { e: [0xaaaaaaaaaaaaaaaa, 0xbbbbbbbbbbbbbbbb, 0xcccccccccccccccc, 0x1111111111111111] };
    let our_result = a.mul(&b);
    let ref_result = reduce_reference(&jolt_inlines_bigint::bigint256_mul(a.e, b.e));
    assert_eq!(our_result.e, ref_result, "mul mismatch:\n  ours: {:x?}\n  ref:  {:x?}", our_result.e, ref_result);

    println!("OK");
}

fn test_field_inv() {
    print!("test_field_inv... ");

    // First test: verify 7^2 reduces correctly
    let seven = Fp { e: [7, 0, 0, 0] };
    let forty_nine = seven.mul(&seven);
    assert_eq!(forty_nine.e, [49, 0, 0, 0], "7*7 != 49: {:x?}", forty_nine.e);

    // Test a few squarings to check for accumulated errors
    let mut x = Fp { e: [7, 0, 0, 0] };
    for i in 0..10 {
        let old = x.clone();
        x = x.square();
        // Verify x < p
        assert!(!gte(&x.e, &P), "x >= p after squaring step {}", i);
    }

    // Compute 7^-1 using Fermat's little theorem: 7^(p-2) mod p
    let a = Fp { e: [7, 0, 0, 0] };
    let a_inv = a.inv();
    let product = a.mul(&a_inv);
    if product != Fp::one() {
        // Debug: print intermediate values
        println!("\n  7^-1 = {:x?}", a_inv.e);
        println!("  7 * 7^-1 = {:x?}", product.e);
        // Python says 7^-1 = 0x249249246db6db6d_db6db6db6db6db6d_b6db6db700000000_0000000000000000
        let expected_inv: [u64; 4] = [0x0000000000000000, 0xb6db6db700000000, 0xdb6db6db6db6db6d, 0x249249246db6db6d];
        println!("  expected = {:x?}", expected_inv);
        assert_eq!(a_inv.e, expected_inv, "7^-1 doesn't match Python");
    }
    assert_eq!(product, Fp::one(), "7 * 7^-1 != 1");

    println!("OK");
}

fn test_point_on_curve() {
    print!("test_point_on_curve... ");
    let gx = Fp { e: GX };
    let gy = Fp { e: GY };

    // First test: gx^2 should match Python
    let gx2 = gx.square();
    let expected_gx2: [u64; 4] = [0x002ae56c426b3f8c, 0x33b699495d694dd1, 0x81819a5e0e3690d8, 0x98f6b84d29bef2b2];
    assert_eq!(gx2.e, expected_gx2, "gx^2 mismatch:\n  got:      {:x?}\n  expected: {:x?}", gx2.e, expected_gx2);

    let a = Fp { e: P }.sub_inner(&Fp { e: [3, 0, 0, 0] });
    let b = Fp { e: B };

    let gx3 = gx2.mul(&gx);
    let expected_gx3: [u64; 4] = [0x60f29c8f83bbd509, 0x497801f461809fcd, 0xb85f88944be7a619, 0x3c609d594a3eae9c];
    assert_eq!(gx3.e, expected_gx3, "gx^3 mismatch:\n  got:      {:x?}\n  expected: {:x?}", gx3.e, expected_gx3);

    let ax = gx.mul(&a);
    let expected_ax: [u64; 4] = [0x221c542e7635b83c, 0x9af5877e763e651d, 0x15c94b4fd5133d28, 0xbeb88a255c7b392a];
    assert_eq!(ax.e, expected_ax, "ax mismatch:\n  got:      {:x?}\n  expected: {:x?}", ax.e, expected_ax);

    let sum1 = gx3.add(&ax);
    let expected_sum1: [u64; 4] = [0x830ef0bdf9f18d45, 0xe46d8972d7bf04ea, 0xce28d3e420fae341, 0xfb19277ea6b9e7c6];
    assert_eq!(sum1.e, expected_sum1, "gx3+ax mismatch:\n  got:      {:x?}\n  expected: {:x?}", sum1.e, expected_sum1);

    let y2 = gy.square();
    let rhs = sum1.add(&b);
    let expected_rhs: [u64; 4] = [0xbedd2cfc21c3ed91, 0x498a9022a412b5e0, 0x82149139979369fe, 0x55df5d5850f47bad];
    assert_eq!(rhs.e, expected_rhs, "rhs mismatch:\n  got:      {:x?}\n  expected: {:x?}", rhs.e, expected_rhs);
    assert_eq!(y2, rhs, "Generator not on curve!");

    println!("OK");
}

fn test_point_add() {
    print!("test_point_add... ");
    // Test G + G = 2*G by doing both add(G,G) and double(G)
    // Using our point operations

    let gx = Fp { e: GX };
    let gy = Fp { e: GY };

    // Double: s = (3*x^2 + a) / (2*y)
    let a = Fp { e: P }.sub_inner(&Fp { e: [3, 0, 0, 0] });
    let x2 = gx.square();
    let three_x2 = x2.add(&x2).add(&x2);
    let num = three_x2.add(&a);
    let den = gy.dbl();
    let s = num.mul(&den.inv());
    let x3 = s.square().sub(&gx.dbl());
    let y3 = s.mul(&gx.sub(&x3)).sub(&gy);

    // Verify 2G is on the curve
    let y3_sq = y3.square();
    let x3_cube = x3.square().mul(&x3);
    let ax3 = x3.mul(&a);
    let rhs = x3_cube.add(&ax3).add(&Fp { e: B });
    assert_eq!(y3_sq, rhs, "2G not on curve!");

    println!("OK");
}

fn test_ecdsa() {
    print!("test_ecdsa (full verification)... ");

    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    fn hex_to_bytes32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    let sk_bytes = hex_to_bytes32("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let signing_key = SigningKey::from_bytes((&sk_bytes).into()).unwrap();
    let verifying_key = signing_key.verifying_key();

    let digest = hex_to_bytes32("4847be4ac21fe68a06d6364bd78467c183f30a857ad8f656219f7c40307c8edf");
    let sig: p256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();

    let pk_point = verifying_key.to_encoded_point(false);
    let pk_x: [u8; 32] = pk_point.x().unwrap().as_slice().try_into().unwrap();
    let pk_y: [u8; 32] = pk_point.y().unwrap().as_slice().try_into().unwrap();
    let sig_bytes = sig.to_bytes();
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&sig_bytes[..32]);
    sig_s.copy_from_slice(&sig_bytes[32..]);

    // Verify using p256 crate first
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    assert!(verifying_key.verify_prehash(&digest, &sig).is_ok(), "p256 crate verify failed");

    // Now verify step by step with our code
    let be_to_limbs = |bytes: &[u8; 32]| -> [u64; 4] {
        let mut e = [0u64; 4];
        for i in 0..4 {
            let off = (3 - i) * 8;
            e[i] = u64::from_be_bytes(bytes[off..off+8].try_into().unwrap());
        }
        e
    };

    let get_bit = |limbs: &[u64; 4], bit: usize| -> usize {
        ((limbs[bit / 64] >> (bit % 64)) & 1) as usize
    };

    // Parse scalars
    let r_limbs = be_to_limbs(&sig_r);
    let s_limbs = be_to_limbs(&sig_s);
    let z_limbs = be_to_limbs(&digest);

    // s^-1 mod n
    let s_fn = Fn_t { e: s_limbs };
    let s_inv = s_fn.inv();
    // Verify: s * s_inv = 1 mod n
    let check = s_fn.mul(&s_inv);
    assert_eq!(check.e, [1, 0, 0, 0], "s * s^-1 != 1 mod n: {:x?}", check.e);

    let u1 = Fn_t { e: z_limbs }.mul(&s_inv);
    let u2 = Fn_t { e: r_limbs }.mul(&s_inv);

    println!("u1 = {:x?}", u1.e);
    println!("u2 = {:x?}", u2.e);

    // Build lookup table: [inf, G, Q, G+Q]
    let g_pt = Pt { x: Fp { e: GX }, y: Fp { e: GY } };
    let q_pt = Pt { x: Fp { e: be_to_limbs(&pk_x) }, y: Fp { e: be_to_limbs(&pk_y) } };

    // Verify Q is on curve
    let a_coeff = Fp { e: P }.sub_inner(&Fp { e: [3, 0, 0, 0] });
    let y2 = q_pt.y.square();
    let x3 = q_pt.x.square().mul(&q_pt.x);
    let ax = q_pt.x.mul(&a_coeff);
    let rhs = x3.add(&ax).add(&Fp { e: B });
    assert_eq!(y2, rhs, "Q not on curve");

    let gq = pt_add(&g_pt, &q_pt);
    let table = [Pt { x: Fp::zero(), y: Fp::zero() }, g_pt.clone(), q_pt.clone(), gq];

    // Shamir's trick
    let mut acc = Pt { x: Fp::zero(), y: Fp::zero() };
    for bit in (0..256).rev() {
        acc = pt_double(&acc);
        let b1 = get_bit(&u1.e, bit);
        let b2 = get_bit(&u2.e, bit);
        let idx = b1 + 2 * b2;
        if idx != 0 {
            acc = pt_add(&acc, &table[idx]);
        }
    }

    assert!(!acc.x.is_zero() || !acc.y.is_zero(), "R is infinity");

    // R.x mod n should equal r
    let mut rx = acc.x.e;
    if gte(&rx, &N) {
        sub_borrow(&mut rx, &N);
    }
    assert_eq!(rx, r_limbs, "R.x mod n != r\n  R.x mod n: {:x?}\n  r:         {:x?}", rx, r_limbs);

    println!("OK");
}

// Minimal Fn (scalar field) for testing
#[derive(Clone, PartialEq, Debug)]
struct Fn_t { e: [u64; 4] }
impl Fn_t {
    fn mul(&self, other: &Fn_t) -> Fn_t {
        let wide = jolt_inlines_bigint::bigint256_mul(self.e, other.e);
        // reduce mod n
        let ref_val = reduce_mod_n_ref(&wide);
        Fn_t { e: ref_val }
    }
    fn inv(&self) -> Fn_t {
        let mut result = Fn_t { e: [1, 0, 0, 0] };
        let mut base = self.clone();
        let exp = [N[0].wrapping_sub(2), N[1], N[2], N[3]];
        for i in 0..4 {
            let mut word = exp[i];
            for _ in 0..64 {
                if word & 1 == 1 { result = result.mul(&base); }
                base = base.mul(&base);
                word >>= 1;
            }
        }
        result
    }
}

fn reduce_mod_n_ref(wide: &[u64; 8]) -> [u64; 4] {
    // Use u128 to compute wide mod n
    let mut val = 0u128;
    let mut result = [0u64; 4];

    // Convert wide to a big number and reduce
    // Simple: iterative reduction using 2^256 mod n
    let r256_mod_n: [u64; 4] = [
        0x0C46353D039CDAAF,
        0x4319055258E8617B,
        0x0000000000000000,
        0x00000000FFFFFFFF,
    ];

    result[0] = wide[0]; result[1] = wide[1]; result[2] = wide[2]; result[3] = wide[3];
    let mut acc = [0u64; 5];
    acc[0] = result[0]; acc[1] = result[1]; acc[2] = result[2]; acc[3] = result[3];

    let high = [wide[4], wide[5], wide[6], wide[7]];
    let prod = jolt_inlines_bigint::bigint256_mul(high, r256_mod_n);

    let mut carry = 0u64;
    for j in 0..4 {
        let (s1, c1) = acc[j].overflowing_add(prod[j]);
        let (s2, c2) = s1.overflowing_add(carry);
        acc[j] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
    acc[4] = carry;

    // Handle prod[4..7]
    let high2 = [prod[4], prod[5], prod[6], prod[7]];
    if high2 != [0; 4] {
        let prod2 = jolt_inlines_bigint::bigint256_mul(high2, r256_mod_n);
        let mut carry2 = 0u64;
        for j in 0..4 {
            let (s1, c1) = acc[j].overflowing_add(prod2[j]);
            let (s2, c2) = s1.overflowing_add(carry2);
            acc[j] = s2;
            carry2 = (c1 as u64) + (c2 as u64);
        }
        acc[4] = acc[4].wrapping_add(carry2);
    }

    while acc[4] > 0 || gte(&[acc[0], acc[1], acc[2], acc[3]], &N) {
        if acc[4] > 0 {
            let overflow = acc[4]; acc[4] = 0;
            let mut c = 0u64;
            for j in 0..4 {
                let (lo, hi) = widening_mul(overflow, r256_mod_n[j]);
                let (s1, c1) = acc[j].overflowing_add(lo);
                let (s2, c2) = s1.overflowing_add(c);
                acc[j] = s2;
                c = hi + (c1 as u64) + (c2 as u64);
            }
            acc[4] = c;
        } else {
            sub_borrow(&mut [acc[0], acc[1], acc[2], acc[3]], &N);
            // need mutable slice... let's do it properly
            let mut tmp = [acc[0], acc[1], acc[2], acc[3]];
            sub_borrow(&mut tmp, &N);
            acc[0] = tmp[0]; acc[1] = tmp[1]; acc[2] = tmp[2]; acc[3] = tmp[3];
        }
    }

    [acc[0], acc[1], acc[2], acc[3]]
}

// Minimal point operations
#[derive(Clone)]
struct Pt { x: Fp, y: Fp }

fn pt_is_inf(p: &Pt) -> bool { p.x.is_zero() && p.y.is_zero() }

fn pt_double(p: &Pt) -> Pt {
    if pt_is_inf(p) || p.y.is_zero() { return Pt { x: Fp::zero(), y: Fp::zero() }; }
    let a = Fp { e: P }.sub_inner(&Fp { e: [3, 0, 0, 0] });
    let x2 = p.x.square();
    let num = x2.add(&x2).add(&x2).add(&a);
    let den = p.y.dbl();
    let s = num.mul(&den.inv());
    let x3 = s.square().sub(&p.x.dbl());
    let y3 = s.mul(&p.x.sub(&x3)).sub(&p.y);
    Pt { x: x3, y: y3 }
}

fn pt_add(p: &Pt, q: &Pt) -> Pt {
    if pt_is_inf(p) { return q.clone(); }
    if pt_is_inf(q) { return p.clone(); }
    if p.x == q.x && p.y == q.y { return pt_double(p); }
    if p.x == q.x { return Pt { x: Fp::zero(), y: Fp::zero() }; }

    let dx = q.x.sub(&p.x);
    let dy = q.y.sub(&p.y);
    let s = dy.mul(&dx.inv());
    let x3 = s.square().sub(&p.x).sub(&q.x);
    let y3 = s.mul(&p.x.sub(&x3)).sub(&p.y);
    Pt { x: x3, y: y3 }
}
