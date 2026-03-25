// test_field.rs — Diagnostic tests for P-256 field multiplication inside the guest.
//
// Exercises bigint256_mul + reduce_p256 on two known inputs:
//   Test 1: 7 * 7 == 49 (trivial, no reduction needed)
//   Test 2: G.x * G.x == known Python value (exercises full NIST reduction)
//
// Returns an error code packed into [u64; 4]:
//   [0] = 0 means all tests passed
//   [0] = 1 means test 1 failed  (7*7 != 49)
//   [0] = 2 means test 2 failed  (G.x^2 mismatch)
//   [1..3] = first limb of the incorrect result (for debugging)

use crate::p256_fast;

/// P-256 generator x coordinate (little-endian u64 limbs).
const GX: [u64; 4] = [
    0xF4A13945D898C296,
    0x77037D812DEB33A0,
    0xF8BCE6E563A440F2,
    0x6B17D1F2E12C4247,
];

/// G.x^2 mod p, computed in Python:
///   gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
///   p  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
///   hex((gx * gx) % p)
///   = 0x98f6b84d29bef2b281819a5e0e3690d833b699495d694dd1002ae56c426b3f8c
const EXPECTED_GX_SQ: [u64; 4] = [
    0x002ae56c426b3f8c,
    0x33b699495d694dd1,
    0x81819a5e0e3690d8,
    0x98f6b84d29bef2b2,
];

/// Run field multiplication diagnostics.
/// Returns [error_code, debug0, debug1, debug2].
pub fn run_tests() -> [u64; 4] {
    // ------------------------------------------------------------------
    // Test 1: 7 * 7 == 49
    // ------------------------------------------------------------------
    let seven: [u64; 4] = [7, 0, 0, 0];
    let wide = p256_fast::bigint256_mul(seven, seven);
    let result = p256_fast::reduce_p256(&wide);
    if result.e != [49, 0, 0, 0] {
        return [1, result.e[0], result.e[1], result.e[2]];
    }

    // ------------------------------------------------------------------
    // Test 2: G.x * G.x == EXPECTED_GX_SQ
    // ------------------------------------------------------------------
    let wide_gx = p256_fast::bigint256_mul(GX, GX);
    let gx_sq = p256_fast::reduce_p256(&wide_gx);
    if gx_sq.e != EXPECTED_GX_SQ {
        return [2, gx_sq.e[0], gx_sq.e[1], gx_sq.e[2]];
    }

    // All passed
    [0, 0, 0, 0]
}
