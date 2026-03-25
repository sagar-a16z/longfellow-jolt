// P-256 ECDSA verification using the jolt-inlines-p256 inline instructions.
// Each field mul/square/div is a single custom RISC-V instruction (~244 virtual cycles).

use jolt_inlines_p256::{P256Fq, P256Fr, P256Point, ecdsa_verify, UnwrapOrSpoilProof};

/// Convert big-endian 32-byte array to [u64; 4] little-endian limbs
fn be_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
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

/// Verify an ECDSA P-256 signature using inline field instructions.
pub fn verify_ecdsa_p256_inline(
    pk_x: &[u8; 32],
    pk_y: &[u8; 32],
    sig_r: &[u8; 32],
    sig_s: &[u8; 32],
    digest: &[u8; 32],
) -> bool {
    let z = P256Fr::from_u64_arr(&be_to_limbs(digest)).unwrap_or_spoil_proof();
    let r = P256Fr::from_u64_arr(&be_to_limbs(sig_r)).unwrap_or_spoil_proof();
    let s = P256Fr::from_u64_arr(&be_to_limbs(sig_s)).unwrap_or_spoil_proof();

    let q_limbs: [u64; 8] = {
        let x = be_to_limbs(pk_x);
        let y = be_to_limbs(pk_y);
        [x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3]]
    };
    let q = P256Point::from_u64_arr(&q_limbs).unwrap_or_spoil_proof();

    ecdsa_verify(z, r, s, q).unwrap_or_spoil_proof();
    true
}
