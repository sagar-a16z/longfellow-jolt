// Longfellow-Jolt: mDOC credential verification as a Jolt ZK proof.
//
// Verifies an ISO 18013-5 mDOC (mobile document) credential inside the Jolt
// zkVM with zero-knowledge (BlindFold). The credential contents are hidden
// from the verifier; only the public inputs (timestamp, session transcript,
// expected attribute digests) are visible.

extern crate alloc;
use alloc::vec::Vec;

use jolt_inlines_p256::{P256Fr, P256Point, ecdsa_verify, UnwrapOrSpoilProof};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    jolt_inlines_sha2::Sha256::digest(data)
}

/// Convert big-endian 32-byte array to [u64; 4] little-endian limbs.
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

/// Verify an ECDSA P-256 signature over a SHA-256 digest.
fn verify_ecdsa_p256(
    pk_x: &[u8; 32], pk_y: &[u8; 32],
    sig_r: &[u8; 32], sig_s: &[u8; 32],
    digest: &[u8; 32],
) -> bool {
    let z = P256Fr::from_u64_arr(&be_to_limbs(digest)).unwrap_or_spoil_proof();
    let r = P256Fr::from_u64_arr(&be_to_limbs(sig_r)).unwrap_or_spoil_proof();
    let s = P256Fr::from_u64_arr(&be_to_limbs(sig_s)).unwrap_or_spoil_proof();
    let q_limbs = {
        let x = be_to_limbs(pk_x);
        let y = be_to_limbs(pk_y);
        [x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3]]
    };
    let q = P256Point::from_u64_arr(&q_limbs).unwrap_or_spoil_proof();
    ecdsa_verify(z, r, s, q).unwrap_or_spoil_proof();
    true
}

/// Lexicographic date comparison on ISO 8601 byte strings.
fn date_leq(a: &[u8], b: &[u8]) -> bool {
    let len = if a.len() < b.len() { a.len() } else { b.len() };
    for i in 0..len {
        if a[i] < b[i] { return true; }
        if a[i] > b[i] { return false; }
    }
    a.len() <= b.len()
}

/// Find a byte pattern in a buffer starting from offset.
fn find_pattern(buf: &[u8], pattern: &[u8], start: usize) -> Option<usize> {
    if pattern.is_empty() || buf.len() < pattern.len() { return None; }
    let end = buf.len() - pattern.len() + 1;
    for i in start..end {
        if &buf[i..i + pattern.len()] == pattern {
            return Some(i);
        }
    }
    None
}

/// Extract a CBOR tagged date string (c0 74 = tag(0) + text(20)) near the given offset.
fn extract_tagged_date(mso: &[u8], keyword_offset: usize) -> Option<[u8; 20]> {
    let search_end = if keyword_offset + 64 < mso.len() { keyword_offset + 64 } else { mso.len() };
    for i in keyword_offset..search_end.saturating_sub(21) {
        if mso[i] == 0xc0 && mso[i + 1] == 0x74 {
            let mut date = [0u8; 20];
            date.copy_from_slice(&mso[i + 2..i + 22]);
            return Some(date);
        }
    }
    None
}

/// Extract SHA-256 digests from the MSO's valueDigests section.
fn extract_digests(mso: &[u8]) -> Vec<(u8, [u8; 32])> {
    let mut digests = Vec::new();
    let vd = b"valueDigests";
    let pos = match find_pattern(mso, vd, 0) {
        Some(p) => p + vd.len(),
        None => return digests,
    };
    let mut i = pos;
    while i + 35 < mso.len() {
        if mso[i] == 0x58 && mso[i + 1] == 0x20 {
            let key = if i > 0 { mso[i - 1] } else { 0 };
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&mso[i + 2..i + 34]);
            digests.push((key, digest));
            i += 34;
        } else {
            i += 1;
        }
        if i + 13 < mso.len() && &mso[i..i + 13] == b"deviceKeyInfo" {
            break;
        }
    }
    digests
}

/// Extract device public key (x, y) from MSO's deviceKeyInfo COSE_Key.
fn extract_device_key(mso: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let dk = b"deviceKey";
    let pos = find_pattern(mso, dk, 0)?;
    let start = pos + dk.len();

    // COSE_Key x-coordinate: key -2 (0x21), bstr(32) (0x58 0x20)
    let x_pos = find_pattern(mso, &[0x21, 0x58, 0x20], start)?;
    if x_pos + 35 > mso.len() { return None; }
    let mut pk_x = [0u8; 32];
    pk_x.copy_from_slice(&mso[x_pos + 3..x_pos + 35]);

    // COSE_Key y-coordinate: key -3 (0x22), bstr(32) (0x58 0x20)
    let y_pos = find_pattern(mso, &[0x22, 0x58, 0x20], x_pos + 35)?;
    if y_pos + 35 > mso.len() { return None; }
    let mut pk_y = [0u8; 32];
    pk_y.copy_from_slice(&mso[y_pos + 3..y_pos + 35]);

    Some((pk_x, pk_y))
}

// ---------------------------------------------------------------------------
// The provable function
// ---------------------------------------------------------------------------

/// Verify an mDOC credential with selective attribute disclosure.
///
/// Credential (private input — hidden from verifier):
///   [4:mso_len][mso][32:issuer_pk_x][32:issuer_pk_y]
///   [32:issuer_sig_r][32:issuer_sig_s][32:device_sig_r][32:device_sig_s]
///   [2:n_attrs][for each: [4:preimage_len][preimage]]
///
/// Public inputs (visible to verifier):
///   [20:now][4:transcript_len][transcript]
///   [2:n_expected_digests][32 each: expected_digest]
///
/// Returns 1 if valid, 2-9 for specific failures, 0 for parse errors.
#[jolt::provable(max_input_size = 65536, max_trace_length = 2097152, stack_size = 4194304, heap_size = 33554432)]
fn verify_mdoc(credential: jolt::PrivateInput<Vec<u8>>, public_inputs: Vec<u8>) -> u32 {
    let credential: &Vec<u8> = &credential;

    // --- Parse credential ---
    let mut off = 0usize;
    if credential.len() < 4 { return 0; }

    let mso_len = u32::from_le_bytes([
        credential[off], credential[off+1], credential[off+2], credential[off+3]
    ]) as usize;
    off += 4;
    if off + mso_len > credential.len() { return 0; }
    let mso = &credential[off..off + mso_len];
    off += mso_len;

    if off + 192 > credential.len() { return 0; }
    let mut issuer_pk_x = [0u8; 32]; issuer_pk_x.copy_from_slice(&credential[off..off+32]); off += 32;
    let mut issuer_pk_y = [0u8; 32]; issuer_pk_y.copy_from_slice(&credential[off..off+32]); off += 32;
    let mut issuer_sig_r = [0u8; 32]; issuer_sig_r.copy_from_slice(&credential[off..off+32]); off += 32;
    let mut issuer_sig_s = [0u8; 32]; issuer_sig_s.copy_from_slice(&credential[off..off+32]); off += 32;
    let mut device_sig_r = [0u8; 32]; device_sig_r.copy_from_slice(&credential[off..off+32]); off += 32;
    let mut device_sig_s = [0u8; 32]; device_sig_s.copy_from_slice(&credential[off..off+32]); off += 32;

    if off + 2 > credential.len() { return 0; }
    let n_attrs = u16::from_le_bytes([credential[off], credential[off+1]]) as usize;
    off += 2;

    let mut attr_preimages: Vec<Vec<u8>> = Vec::with_capacity(n_attrs);
    for _ in 0..n_attrs {
        if off + 4 > credential.len() { return 0; }
        let plen = u32::from_le_bytes([
            credential[off], credential[off+1], credential[off+2], credential[off+3]
        ]) as usize;
        off += 4;
        if off + plen > credential.len() { return 0; }
        attr_preimages.push(credential[off..off+plen].to_vec());
        off += plen;
    }

    // --- Parse public inputs ---
    let mut poff = 0usize;
    if public_inputs.len() < 26 { return 0; }
    let now = &public_inputs[poff..poff+20]; poff += 20;

    let tr_len = u32::from_le_bytes([
        public_inputs[poff], public_inputs[poff+1],
        public_inputs[poff+2], public_inputs[poff+3]
    ]) as usize;
    poff += 4;
    if poff + tr_len > public_inputs.len() { return 0; }
    let transcript = &public_inputs[poff..poff+tr_len];
    poff += tr_len;

    if poff + 2 > public_inputs.len() { return 0; }
    let n_expected = u16::from_le_bytes([public_inputs[poff], public_inputs[poff+1]]) as usize;
    poff += 2;
    if poff + n_expected * 32 > public_inputs.len() { return 0; }

    let mut expected_digests: Vec<[u8; 32]> = Vec::with_capacity(n_expected);
    for _ in 0..n_expected {
        let mut d = [0u8; 32];
        d.copy_from_slice(&public_inputs[poff..poff+32]);
        poff += 32;
        expected_digests.push(d);
    }

    // === Step 1: SHA-256 of issuer's COSE_Sign1 structure ===
    jolt::start_cycle_tracking("2_sha256_issuer");
    let cose1_prefix: [u8; 18] = [
        0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75,
        0x72, 0x65, 0x31, 0x43, 0xA1, 0x01, 0x26, 0x40, 0x59,
    ];
    let mso_len_be = [(mso_len >> 8) as u8, (mso_len & 0xFF) as u8];
    let mut hash_input = Vec::with_capacity(cose1_prefix.len() + 2 + mso_len);
    hash_input.extend_from_slice(&cose1_prefix);
    hash_input.extend_from_slice(&mso_len_be);
    hash_input.extend_from_slice(mso);
    let issuer_digest = sha256(&hash_input);
    jolt::end_cycle_tracking("2_sha256_issuer");

    // === Step 2: Issuer ECDSA P-256 verification ===
    jolt::start_cycle_tracking("3_ecdsa_issuer");
    if !verify_ecdsa_p256(&issuer_pk_x, &issuer_pk_y, &issuer_sig_r, &issuer_sig_s, &issuer_digest) {
        return 2;
    }
    jolt::end_cycle_tracking("3_ecdsa_issuer");

    // === Step 3: Extract device public key from MSO ===
    jolt::start_cycle_tracking("4_extract_device_key");
    let (device_pk_x, device_pk_y) = match extract_device_key(mso) {
        Some(k) => k,
        None => return 3,
    };
    jolt::end_cycle_tracking("4_extract_device_key");

    // === Step 4: SHA-256 of DeviceAuthentication COSE structure ===
    jolt::start_cycle_tracking("5_sha256_device_auth");
    let doc_type = b"org.iso.18013.5.1.mDL";

    // DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]
    let mut device_auth = Vec::new();
    device_auth.push(0x84); // array(4)
    device_auth.push(0x74); // text(20)
    device_auth.extend_from_slice(b"DeviceAuthentication");
    device_auth.extend_from_slice(transcript);
    device_auth.push(0x75); // text(21)
    device_auth.extend_from_slice(doc_type);
    device_auth.extend_from_slice(&[0xD8, 0x18, 0x41, 0xA0]); // Tag(24) bytes(map(0))

    // Wrap in Tag(24) + bstr header
    let da_len = device_auth.len();
    let mut tagged_da = Vec::new();
    tagged_da.push(0xD8); tagged_da.push(0x18);
    if da_len < 24 { tagged_da.push(0x40 + da_len as u8); }
    else if da_len < 256 { tagged_da.push(0x58); tagged_da.push(da_len as u8); }
    else { tagged_da.push(0x59); tagged_da.push((da_len >> 8) as u8); tagged_da.push((da_len & 0xFF) as u8); }
    tagged_da.extend_from_slice(&device_auth);

    // COSE_Sign1 Sig_structure
    let mut device_sig_input = Vec::new();
    device_sig_input.push(0x84); // array(4)
    device_sig_input.push(0x6A); // text(10)
    device_sig_input.extend_from_slice(b"Signature1");
    device_sig_input.extend_from_slice(&[0x43, 0xA1, 0x01, 0x26]); // protected: {1: -7}
    device_sig_input.push(0x40); // external_aad: empty
    let tda_len = tagged_da.len();
    if tda_len < 24 { device_sig_input.push(0x40 + tda_len as u8); }
    else if tda_len < 256 { device_sig_input.push(0x58); device_sig_input.push(tda_len as u8); }
    else { device_sig_input.push(0x59); device_sig_input.push((tda_len >> 8) as u8); device_sig_input.push((tda_len & 0xFF) as u8); }
    device_sig_input.extend_from_slice(&tagged_da);

    let transcript_digest = sha256(&device_sig_input);
    jolt::end_cycle_tracking("5_sha256_device_auth");

    // === Step 5: Device ECDSA P-256 verification ===
    jolt::start_cycle_tracking("6_ecdsa_device");
    if !verify_ecdsa_p256(&device_pk_x, &device_pk_y, &device_sig_r, &device_sig_s, &transcript_digest) {
        return 4;
    }
    jolt::end_cycle_tracking("6_ecdsa_device");

    // === Step 6: Date validation ===
    jolt::start_cycle_tracking("7_date_validation");
    if let Some(vf_pos) = find_pattern(mso, b"validFrom", 0) {
        if let Some(valid_from) = extract_tagged_date(mso, vf_pos) {
            if !date_leq(&valid_from, now) { return 5; }
        }
    }
    if let Some(vu_pos) = find_pattern(mso, b"validUntil", 0) {
        if let Some(valid_until) = extract_tagged_date(mso, vu_pos) {
            if !date_leq(now, &valid_until) { return 6; }
        }
    }
    jolt::end_cycle_tracking("7_date_validation");

    // === Step 7: Attribute digest verification ===
    jolt::start_cycle_tracking("8_attribute_verification");
    if n_attrs != expected_digests.len() { return 7; }
    let mso_digests = extract_digests(mso);
    for i in 0..n_attrs {
        let attr_hash = sha256(&attr_preimages[i]);
        if attr_hash != expected_digests[i] { return 8; }
        let mut found = false;
        for (_, mso_d) in &mso_digests {
            if *mso_d == attr_hash { found = true; break; }
        }
        if !found { return 9; }
    }
    jolt::end_cycle_tracking("8_attribute_verification");

    1 // All checks passed
}
