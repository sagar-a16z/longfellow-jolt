# Longfellow-Jolt

Zero-knowledge mDOC (mobile driver's license) credential verification via [Jolt zkVM](https://github.com/a16z/jolt). A reimplementation of [Google's longfellow-zk](https://github.com/google/longfellow-zk) protocol — the Ligero+sumcheck circuit deployed in Google Wallet for age verification — replacing the hand-rolled C++ circuit with a RISC-V guest program.

Given a real ISO 18013-5 mDOC issued by a trusted IACA, proves:
1. The issuer's P-256 ECDSA signature over the MSO (Mobile Security Object) is valid
2. The device's P-256 ECDSA signature over the session transcript is valid
3. The revealed attributes (e.g. `age_over_18`) hash to digests that appear in the MSO
4. The credential's `validFrom` / `validUntil` dates bracket the verification time

Test data is the first `age_over_18` test mDOC from [longfellow-zk's `mdoc_examples.h`](https://github.com/google/longfellow-zk/blob/main/lib/circuits/mdoc/mdoc_examples.h), signed by the Google TEST IACA mDL issuer.

## Performance (Apple M4)

| Metric | Value |
|---|---|
| Total cycles | 1,190,512 |
| Prover time | 7.40s |
| Verifier time | 0.15s |
| Peak memory (jemalloc) | 1.70 GB |
| `max_trace_length` | 2^21 (2,097,152) |

### Per-section cycle breakdown

| Section | Cycles | % | What it does |
|---|---|---|---|
| `3_ecdsa_issuer` | 494,620 | 41.5% | P-256 ECDSA verify of issuer signature over MSO (Fake-GLV, independent per-point Shamirs) |
| `6_ecdsa_device` | 497,021 | 41.7% | P-256 ECDSA verify of device signature over session transcript |
| `5_sha256_device_auth` | 40,179 | 3.4% | SHA-256 of the CBOR-encoded device authentication transcript |
| `7_date_validation` | 32,207 | 2.7% | Parse `validFrom`/`validUntil` from CBOR, compare against current time |
| `2_sha256_issuer` | 31,083 | 2.6% | SHA-256 of the MSO payload (CBOR-encoded) |
| `8_attribute_verification` | 23,043 | 1.9% | SHA-256 of each revealed attribute's CBOR bstr, match against MSO digests |
| `4_extract_device_key` | 13,336 | 1.1% | Parse device P-256 public key from MSO CBOR |
| serde + overhead | ~59,023 | 5.0% | Jolt postcard deserialization of credential input |

### vs longfellow-zk (C++ Ligero+sumcheck)

longfellow-zk uses a custom Ligero + sumcheck SNARK with two sub-circuits (Fp256 for ECDSA, GF(2^128) for SHA/CBOR) linked by a cross-circuit MAC, ~34K lines of C++. This reimplementation uses a single Jolt execution trace with no composition, ~500 lines of Rust.

## ECDSA approach

Uses the upstream `jolt-inlines-p256` precompile, which implements full P-256 ECDSA verify in ~497K cycles (vs ~3.8M for the pure-Rust `p256` crate compiled as guest code — an ~8× speedup from precompiled field arithmetic). The scalar multiplication uses the [Fake-GLV](https://ethresear.ch/t/fake-glv-you-dont-need-an-efficient-endomorphism-to-implement-glv-like-scalar-multiplication-in-snark-circuits/20394) technique: the prover supplies a half-GCD decomposition `(a_i, b_i)` of each `u_i = z/s, r/s`, and the guest verifies via two independent 2-scalar 128-bit Shamir MSMs — one per point — binding each `R_i = u_i * P`.

Independent per-point Shamirs (rather than a combined 4-scalar check) are required for soundness; see [a16z/jolt#1458](https://github.com/a16z/jolt/pull/1458).

## Running

```bash
RUST_LOG=info cargo run --release --bin longfellow-jolt
```

## Project structure

```
guest/src/lib.rs       # Jolt guest: provable verify_mdoc function
src/main.rs            # Host: build test credential, prove, verify, memory trace
src/bin/test_p256.rs   # Host-side P-256 arithmetic sanity test
docs/                  # Design notes
```

## Dependencies

All Jolt crates (`jolt-sdk`, `jolt-core`, `jolt-inlines-{p256,bigint,sha2}`) track [a16z/jolt](https://github.com/a16z/jolt) branch `main`.
