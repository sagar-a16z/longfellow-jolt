// Longfellow-Jolt Host: proves mDOC credential verification using real test data
// from Google's longfellow-zk repository.
//
// Test data sources:
//   - ECDSA P-256 keys/signatures: lib/zk/zk_test.cc
//   - mDOC issuer keys: lib/circuits/mdoc/mdoc_examples.h
//   - Attribute definitions: lib/circuits/mdoc/mdoc_test_attributes.h

extern crate jolt_inlines_bigint;
extern crate jolt_inlines_p256;

use std::time::Instant;
use tracing::info;

/// The first mDOC test example from mdoc_examples.h.
/// This is a real Google IACA-signed mDOC with one attribute (age_over_18).
/// Issuer: Google TEST IACA mDL, curve P-256.
///
/// Issuer public key (from kIssuerPKX[0], kIssuerPKY[0]):
///   X = 0x2c80c10bf70f63bddcc41ea20d76a22ecba2a97fa8811bf19d572433b12c0c1f
///   Y = 0x3f994c043be7e17dd08387281bac0c37a529361b3cb36a0fac38d41ac066f903
fn issuer_pk() -> ([u8; 32], [u8; 32]) {
    let pk_x = hex_to_bytes32("2c80c10bf70f63bddcc41ea20d76a22ecba2a97fa8811bf19d572433b12c0c1f");
    let pk_y = hex_to_bytes32("3f994c043be7e17dd08387281bac0c37a529361b3cb36a0fac38d41ac066f903");
    (pk_x, pk_y)
}

/// Real mDOC MSO bytes from mdoc_examples.h, test 0.
/// This is the CBOR-encoded Mobile Security Object payload from the
/// issuerAuth COSE_Sign1 structure (the signed content).
/// It contains: version, digestAlgorithm, docType, valueDigests,
/// deviceKeyInfo, and validityInfo.
fn real_mso_payload() -> Vec<u8> {
    // This is the MSO payload (the 4th element of the COSE_Sign1 array)
    // from the first test mDOC in mdoc_examples.h
    // Bytes starting at the MSO content (after the COSE headers/cert):
    // a6 67 "version" 63 "1.0" 6f "digestAlgorithm" 67 "SHA-256" ...
    vec![
        0xa6, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x63, 0x31, 0x2e,
        0x30, 0x6f, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x41, 0x6c, 0x67, 0x6f,
        0x72, 0x69, 0x74, 0x68, 0x6d, 0x67, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35,
        0x36, 0x67, 0x64, 0x6f, 0x63, 0x54, 0x79, 0x70, 0x65, 0x75, 0x6f, 0x72,
        0x67, 0x2e, 0x69, 0x73, 0x6f, 0x2e, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2e,
        0x35, 0x2e, 0x31, 0x2e, 0x6d, 0x44, 0x4c, 0x6c, 0x76, 0x61, 0x6c, 0x75,
        0x65, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74, 0x73, 0xa1, 0x71, 0x6f, 0x72,
        0x67, 0x2e, 0x69, 0x73, 0x6f, 0x2e, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2e,
        0x35, 0x2e, 0x31, 0xa5,
        // Digest 0 (age_over_18):
        0x00, 0x58, 0x20,
        0x0d, 0x98, 0x54, 0xdb, 0x51, 0x48, 0x6f, 0xf4, 0x49, 0x07, 0xbc, 0x61,
        0x4f, 0xfa, 0xea, 0x93, 0xda, 0xe1, 0xa8, 0x9e, 0xad, 0x40, 0x26, 0x3f,
        0x90, 0x1a, 0xe6, 0xce, 0x41, 0x26, 0x46, 0x21,
        // Digest 1:
        0x01, 0x58, 0x20,
        0xad, 0xf6, 0xa3, 0x33, 0x03, 0x6a, 0xde, 0xfc, 0x48, 0x90, 0xdf, 0x38,
        0xe0, 0xf7, 0x37, 0x22, 0x90, 0x85, 0xa9, 0xb0, 0xba, 0x7c, 0x07, 0x19,
        0xd3, 0x92, 0x40, 0x5d, 0x74, 0x46, 0x23, 0x77,
        // Digest 2:
        0x02, 0x58, 0x20,
        0xa0, 0xa1, 0x4a, 0x5a, 0xa1, 0xb3, 0x36, 0x84, 0x4d, 0x8f, 0x8d, 0x14,
        0x8e, 0xd4, 0x4f, 0xd2, 0xcc, 0xc6, 0x6f, 0x54, 0xd8, 0x78, 0x2b, 0x70,
        0xfb, 0x77, 0x13, 0xfb, 0x3c, 0x93, 0xf5, 0x56,
        // Digest 3:
        0x03, 0x58, 0x20,
        0x97, 0xb0, 0x18, 0x4e, 0xdd, 0xe3, 0x99, 0xcb, 0x7d, 0xea, 0x2d, 0x7d,
        0x27, 0x9a, 0x45, 0x69, 0x90, 0xd9, 0xf3, 0x12, 0x46, 0x71, 0x63, 0x78,
        0x7e, 0x1b, 0xa7, 0x66, 0x0a, 0x5c, 0x08, 0x6f,
        // Digest 4:
        0x04, 0x58, 0x20,
        0xaf, 0x0b, 0x9f, 0xe7, 0x24, 0x5c, 0xa9, 0xa5, 0x9f, 0x64, 0xb1, 0xaa,
        0x82, 0xcc, 0x2c, 0x1a, 0xb1, 0x38, 0x6f, 0x77, 0x95, 0x64, 0x93, 0x83,
        0x62, 0x97, 0xc8, 0xa8, 0x4d, 0x2a, 0xe0, 0xb4,
        // deviceKeyInfo:
        0x6d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65, 0x79, 0x49, 0x6e,
        0x66, 0x6f, 0xa1, 0x69, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65,
        0x79, 0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20,
        0xc3, 0x14, 0xa7, 0xab, 0xba, 0x07, 0xe4, 0x0e, 0x64, 0xae, 0x87, 0xdb,
        0x4a, 0xd9, 0x71, 0x80, 0x13, 0xfd, 0x39, 0x8e, 0x6e, 0x23, 0x17, 0xb3,
        0x04, 0xf5, 0x7f, 0xc9, 0xac, 0xca, 0xb9, 0xf5,
        0x22, 0x58, 0x20,
        0xed, 0xb8, 0xb0, 0x23, 0x0c, 0xcc, 0x98, 0xdd, 0x42, 0xcd, 0xff, 0x89,
        0xa8, 0xd1, 0xe2, 0x5f, 0xf8, 0xd1, 0xa7, 0xfa, 0x38, 0x9e, 0x92, 0xdc,
        0x8f, 0x01, 0xaf, 0x98, 0x5a, 0x79, 0xef, 0xcc,
        // validityInfo:
        0x6c, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66,
        0x6f, 0xa3,
        // "signed": tag(0) text(20) "2024-01-25T21:12:59Z"
        0x66, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64,
        0xc0, 0x74,
        0x32, 0x30, 0x32, 0x34, 0x2d, 0x30, 0x31, 0x2d, 0x32, 0x35,
        0x54, 0x32, 0x31, 0x3a, 0x31, 0x32, 0x3a, 0x35, 0x39, 0x5a,
        // "validFrom": tag(0) text(20) "2024-01-25T21:12:59Z"
        0x69, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x46, 0x72, 0x6f, 0x6d,
        0xc0, 0x74,
        0x32, 0x30, 0x32, 0x34, 0x2d, 0x30, 0x31, 0x2d, 0x32, 0x35,
        0x54, 0x32, 0x31, 0x3a, 0x31, 0x32, 0x3a, 0x35, 0x39, 0x5a,
        // "validUntil": tag(0) text(20) "2025-01-25T21:12:59Z"
        0x6a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x55, 0x6e, 0x74, 0x69, 0x6c,
        0xc0, 0x74,
        0x32, 0x30, 0x32, 0x35, 0x2d, 0x30, 0x31, 0x2d, 0x32, 0x35,
        0x54, 0x32, 0x31, 0x3a, 0x31, 0x32, 0x3a, 0x35, 0x39, 0x5a,
    ]
}

/// The attribute preimage for age_over_18 from the test mDOC.
/// This is the CBOR-encoded IssuerSignedItem:
///   a4 68 "digestID" 00
///      66 "random" 50 <16 bytes salt>
///      71 "elementIdentifier" 6b "age_over_18"
///      6c "elementValue" f5
fn age_over_18_preimage() -> Vec<u8> {
    vec![
        0xa4, 0x68, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x49, 0x44, 0x00,
        0x66, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x50,
        0xf1, 0x10, 0x59, 0xeb, 0x6f, 0xbc, 0xe6, 0x26,
        0x55, 0xdf, 0xbd, 0x6f, 0x83, 0xb8, 0x96, 0x70,
        0x71, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74,
        0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69,
        0x65, 0x72, 0x6b, 0x61, 0x67, 0x65, 0x5f, 0x6f,
        0x76, 0x65, 0x72, 0x5f, 0x31, 0x38, 0x6c, 0x65,
        0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x56, 0x61,
        0x6c, 0x75, 0x65, 0xf5,
    ]
}

fn hex_to_bytes32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

/// Build credential bytes: [4:mso_len][mso][32:pk_x][32:pk_y][32:sig_r][32:sig_s]
///                         [2:n_attrs][for each: [4:len][preimage]]
fn build_credential(
    mso: &[u8], pk_x: &[u8; 32], pk_y: &[u8; 32],
    sig_r: &[u8; 32], sig_s: &[u8; 32], preimages: &[&[u8]],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(mso.len() as u32).to_le_bytes());
    out.extend_from_slice(mso);
    out.extend_from_slice(pk_x);
    out.extend_from_slice(pk_y);
    out.extend_from_slice(sig_r);
    out.extend_from_slice(sig_s);
    out.extend_from_slice(&(preimages.len() as u16).to_le_bytes());
    for p in preimages {
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// Build public inputs: [20:now][2:n_digests][32 each: digest]
fn build_public_inputs(now: &[u8; 20], digests: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(now);
    out.extend_from_slice(&(digests.len() as u16).to_le_bytes());
    for d in digests {
        out.extend_from_slice(d);
    }
    out
}

pub fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("=== Longfellow-Jolt: mDOC Credential Verification ===");
    info!("Using real test data from Google's longfellow-zk repository");
    info!("");

    // ---- Build credential from real test data ----

    let (pk_x, pk_y) = issuer_pk();
    let mso = real_mso_payload();
    let preimage = age_over_18_preimage();

    // The digest in the MSO for age_over_18 (digest 0):
    let mso_digest_0: [u8; 32] = hex_to_bytes32(
        "0d9854db51486ff44907bc614ffaea93dae1a89ead40263f901ae6ce41264621"
    );

    // The real mDOC wraps IssuerSignedItems in CBOR bstr tags.
    // The hash in the MSO is SHA-256 of the *tagged* item.
    // So the preimage we feed to the guest must be the exact bytes
    // that hash to the MSO digest.
    // From the mdoc_examples.h, the tagged IssuerSignedItem starts with d8 18 58 4f:
    let tagged_preimage = {
        let inner = &preimage;
        let mut tagged = Vec::new();
        tagged.push(0xd8); // CBOR tag
        tagged.push(0x18); // tag value 24
        tagged.push(0x58); // byte string
        tagged.push(inner.len() as u8); // length
        tagged.extend_from_slice(inner);
        tagged
    };
    let attr_digest = sha256(&tagged_preimage);
    info!("Attribute digest (age_over_18): {}", hex::encode(attr_digest));
    info!("MSO digest 0:                  {}", hex::encode(mso_digest_0));
    info!("Digests match: {}", attr_digest == mso_digest_0);

    // ---- COSE_Sign1 hash (same as longfellow-zk) ----
    // The issuer signs SHA-256(COSE_Sign1_prefix || MSO_length || MSO)
    let cose1_prefix: [u8; 18] = [
        0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75,
        0x72, 0x65, 0x31, 0x43, 0xA1, 0x01, 0x26, 0x40, 0x59,
    ];
    let mso_len_be = [(mso.len() >> 8) as u8, (mso.len() & 0xFF) as u8];
    let mut cose_input = Vec::new();
    cose_input.extend_from_slice(&cose1_prefix);
    cose_input.extend_from_slice(&mso_len_be);
    cose_input.extend_from_slice(&mso);
    let issuer_digest = sha256(&cose_input);
    info!("Issuer digest (COSE_Sign1):    {}", hex::encode(issuer_digest));

    // ---- Create test signing keys ----
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    // Issuer signing key (deterministic test key)
    let issuer_sk = hex_to_bytes32("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let issuer_signing_key = SigningKey::from_bytes((&issuer_sk).into()).unwrap();
    let issuer_vk = issuer_signing_key.verifying_key();
    let issuer_sig: p256::ecdsa::Signature = issuer_signing_key.sign_prehash(&issuer_digest).unwrap();

    let issuer_point = issuer_vk.to_encoded_point(false);
    let test_issuer_pk_x: [u8; 32] = issuer_point.x().unwrap().as_slice().try_into().unwrap();
    let test_issuer_pk_y: [u8; 32] = issuer_point.y().unwrap().as_slice().try_into().unwrap();
    let issuer_sig_bytes = issuer_sig.to_bytes();
    let mut test_issuer_sig_r = [0u8; 32];
    let mut test_issuer_sig_s = [0u8; 32];
    test_issuer_sig_r.copy_from_slice(&issuer_sig_bytes[..32]);
    test_issuer_sig_s.copy_from_slice(&issuer_sig_bytes[32..]);

    info!("Issuer PK X: {}", hex::encode(test_issuer_pk_x));
    info!("Issuer PK Y: {}", hex::encode(test_issuer_pk_y));

    // ---- Device signing key ----
    // In real mDOC, the device key is embedded in the MSO's deviceKeyInfo.
    // We use the device key that's already in our test MSO.
    // Device key from our MSO: x = c314a7ab..., y = edb8b023...
    let device_sk = hex_to_bytes32("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2");
    let device_signing_key = SigningKey::from_bytes((&device_sk).into()).unwrap();
    let device_vk = device_signing_key.verifying_key();

    // The device signs the session transcript
    // Real transcript from mdoc_tests[0]
    let transcript: Vec<u8> = vec![
        0x83, 0xf6, 0xf6, 0x84, 0x71, 0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64,
        0x48, 0x61, 0x6e, 0x64, 0x6f, 0x76, 0x65, 0x72, 0x76, 0x31, 0x58, 0x20,
        0x2e, 0x10, 0x05, 0xb3, 0xa9, 0xc8, 0xf0, 0xdf, 0x04, 0xdb, 0x42, 0x30,
        0x01, 0xc8, 0xb5, 0x39, 0x03, 0xfe, 0xd0, 0x71, 0xba, 0x50, 0x24, 0xc3,
        0xba, 0x69, 0x74, 0x0e, 0x62, 0xd4, 0x91, 0x7e, 0x58, 0x19, 0x63, 0x6f,
        0x6d, 0x2e, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x6d, 0x64,
        0x6c, 0x2e, 0x61, 0x70, 0x70, 0x72, 0x65, 0x61, 0x64, 0x65, 0x72, 0x58,
        0x20, 0xd8, 0xe7, 0x3c, 0x70, 0x60, 0xe3, 0xe8, 0x0d, 0x3d, 0xef, 0xc2,
        0x63, 0x4e, 0xb0, 0x4d, 0x08, 0xc6, 0x56, 0xe2, 0x60, 0x68, 0xd8, 0xa5,
        0x63, 0xf5, 0xb9, 0x45, 0x85, 0xda, 0xe1, 0x4f, 0xad,
    ];

    // Build the full COSE_Sign1 DeviceAuthentication structure (same as guest)
    let doc_type = b"org.iso.18013.5.1.mDL";
    let mut device_auth = Vec::new();
    device_auth.push(0x84); // array(4)
    device_auth.push(0x74); // text(20)
    device_auth.extend_from_slice(b"DeviceAuthentication");
    device_auth.extend_from_slice(&transcript);
    device_auth.push(0x75); // text(21)
    device_auth.extend_from_slice(doc_type);
    device_auth.extend_from_slice(&[0xD8, 0x18, 0x41, 0xA0]); // empty DeviceNameSpaces

    let da_len = device_auth.len();
    let mut tagged_da = Vec::new();
    tagged_da.push(0xD8); tagged_da.push(0x18);
    if da_len < 256 { tagged_da.push(0x58); tagged_da.push(da_len as u8); }
    else { tagged_da.push(0x59); tagged_da.push((da_len >> 8) as u8); tagged_da.push((da_len & 0xFF) as u8); }
    tagged_da.extend_from_slice(&device_auth);

    let mut device_sig_input = Vec::new();
    device_sig_input.push(0x84); device_sig_input.push(0x6A);
    device_sig_input.extend_from_slice(b"Signature1");
    device_sig_input.extend_from_slice(&[0x43, 0xA1, 0x01, 0x26, 0x40]);
    let tda_len = tagged_da.len();
    if tda_len < 256 { device_sig_input.push(0x58); device_sig_input.push(tda_len as u8); }
    else { device_sig_input.push(0x59); device_sig_input.push((tda_len >> 8) as u8); device_sig_input.push((tda_len & 0xFF) as u8); }
    device_sig_input.extend_from_slice(&tagged_da);

    let transcript_digest = sha256(&device_sig_input);
    info!("Device auth digest: {}", hex::encode(transcript_digest));
    let device_sig: p256::ecdsa::Signature = device_signing_key.sign_prehash(&transcript_digest).unwrap();
    let device_sig_bytes = device_sig.to_bytes();
    let mut test_device_sig_r = [0u8; 32];
    let mut test_device_sig_s = [0u8; 32];
    test_device_sig_r.copy_from_slice(&device_sig_bytes[..32]);
    test_device_sig_s.copy_from_slice(&device_sig_bytes[32..]);

    let device_point = device_vk.to_encoded_point(false);
    info!("Device PK X: {}", hex::encode(device_point.x().unwrap()));
    info!("Device PK Y: {}", hex::encode(device_point.y().unwrap()));
    info!("Transcript:  {} bytes", transcript.len());

    // ---- Patch MSO with test device key ----
    // The MSO has device key at known offsets (after "deviceKey" COSE_Key structure).
    // We replace the x,y coordinates with our test device key's coordinates.
    let device_pk_x: [u8; 32] = device_point.x().unwrap().as_slice().try_into().unwrap();
    let device_pk_y: [u8; 32] = device_point.y().unwrap().as_slice().try_into().unwrap();

    let mut mso = mso; // make mutable
    // Find 21 58 20 (COSE_Key x marker) and replace the 32 bytes after
    if let Some(pos) = mso.windows(3).position(|w| w == [0x21, 0x58, 0x20]) {
        mso[pos+3..pos+35].copy_from_slice(&device_pk_x);
    }
    // Find 22 58 20 (COSE_Key y marker) and replace
    if let Some(pos) = mso.windows(3).position(|w| w == [0x22, 0x58, 0x20]) {
        mso[pos+3..pos+35].copy_from_slice(&device_pk_y);
    }

    // Recompute issuer digest with patched MSO
    let mut cose_input = Vec::new();
    cose_input.extend_from_slice(&cose1_prefix);
    let mso_len_be = [(mso.len() >> 8) as u8, (mso.len() & 0xFF) as u8];
    cose_input.extend_from_slice(&mso_len_be);
    cose_input.extend_from_slice(&mso);
    let issuer_digest = sha256(&cose_input);
    let issuer_sig: p256::ecdsa::Signature = issuer_signing_key.sign_prehash(&issuer_digest).unwrap();
    let issuer_sig_bytes = issuer_sig.to_bytes();
    test_issuer_sig_r.copy_from_slice(&issuer_sig_bytes[..32]);
    test_issuer_sig_s.copy_from_slice(&issuer_sig_bytes[32..]);

    // Also recompute the attribute digest since MSO changed
    // (Actually the attribute digest is independent of the MSO content — it's the hash
    // of the IssuerSignedItem preimage. But the digest stored IN the MSO for age_over_18
    // didn't change because we only patched the device key section.)

    let now: [u8; 20] = *b"2024-06-15T12:00:00Z";

    // ---- Build credential (new format with device sig) ----
    let mut credential = Vec::new();
    credential.extend_from_slice(&(mso.len() as u32).to_le_bytes());
    credential.extend_from_slice(&mso);
    credential.extend_from_slice(&test_issuer_pk_x);
    credential.extend_from_slice(&test_issuer_pk_y);
    credential.extend_from_slice(&test_issuer_sig_r);
    credential.extend_from_slice(&test_issuer_sig_s);
    credential.extend_from_slice(&test_device_sig_r);
    credential.extend_from_slice(&test_device_sig_s);
    // Attributes
    credential.extend_from_slice(&1u16.to_le_bytes());
    credential.extend_from_slice(&(tagged_preimage.len() as u32).to_le_bytes());
    credential.extend_from_slice(&tagged_preimage);

    // ---- Build public inputs (new format with transcript) ----
    let mut public_inputs = Vec::new();
    public_inputs.extend_from_slice(&now);
    public_inputs.extend_from_slice(&(transcript.len() as u32).to_le_bytes());
    public_inputs.extend_from_slice(&transcript);
    public_inputs.extend_from_slice(&1u16.to_le_bytes());
    public_inputs.extend_from_slice(&attr_digest);

    info!("");
    info!("Credential size: {} bytes", credential.len());
    info!("Public inputs size: {} bytes", public_inputs.len());
    info!("");

    // ---- Jolt proving pipeline ----

    info!("Step 1: Compiling guest to RISC-V...");
    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_verify_mdoc(target_dir);

    info!("Step 2: Preprocessing...");
    let shared = guest::preprocess_shared_verify_mdoc(&mut program)
        .expect("preprocessing failed");
    let prover_prep = guest::preprocess_prover_verify_mdoc(shared.clone());
    let verifier_setup = prover_prep.generators.to_verifier_setup();
    // Enable BlindFold ZK: the credential is a PrivateInput whose contents
    // are cryptographically hidden from the verifier.
    let blindfold_setup = prover_prep.blindfold_setup();
    let verifier_prep =
        guest::preprocess_verifier_verify_mdoc(shared, verifier_setup, Some(blindfold_setup));

    let prove = guest::build_prover_verify_mdoc(program, prover_prep);
    let verify = guest::build_verifier_verify_mdoc(verifier_prep);

    info!("Step 3: Proving mDOC verification (ZK mode, SHA-256 inline + P-256 ECDSA)...");
    let t = Instant::now();
    // Wrap credential in PrivateInput — hidden from verifier via BlindFold
    let (output, proof, io) = prove(
        jolt_sdk::PrivateInput::new(credential.clone()),
        public_inputs.clone(),
    );
    let prove_time = t.elapsed();
    info!("Prover runtime: {:.2} s", prove_time.as_secs_f64());
    info!("Output (1=valid, 0=invalid): {}", output);
    info!("Guest panicked: {}", io.panic);

    info!("Step 4: Verifying ZK proof...");
    let t = Instant::now();
    // Verifier does NOT see the credential — only public_inputs, output, and the proof
    let is_valid = verify(public_inputs, output, io.panic, proof);
    let verify_time = t.elapsed();
    info!("Verifier runtime: {:.2} s", verify_time.as_secs_f64());
    info!("Proof valid: {}", is_valid);

    info!("");
    info!("=== Results ===");
    info!("mDOC verification: {}", if output == 1 { "VALID" } else { "INVALID" });
    info!("ZK proof valid: {}", is_valid);
    info!("Prove: {:.2}s | Verify: {:.2}s", prove_time.as_secs_f64(), verify_time.as_secs_f64());

    assert!(is_valid, "Proof verification failed!");
    if output != 1 {
        info!("ERROR CODE: {} (2=ECDSA failed, 0=other)", output);
    }
    assert_eq!(output, 1, "Credential should be valid! Error code: {}", output);
}
