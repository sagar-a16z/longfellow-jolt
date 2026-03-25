# jolt-inlines-p256

P-256 (secp256r1 / NIST P-256) field arithmetic inline instructions for the [Jolt zkVM](https://github.com/a16z/jolt).

## Overview

This crate provides hardware-accelerated P-256 elliptic curve operations for Jolt, enabling efficient ECDSA signature verification inside zero-knowledge proofs. Each field multiplication is a single custom RISC-V instruction that expands into ~246 verified virtual instructions.

## Performance

| Operation | Cycles |
|-----------|-------:|
| Base field multiply (MULQ) | ~246 |
| Base field square (SQUAREQ) | ~230 |
| Base field divide (DIVQ) | ~260 |
| Scalar field multiply (MULR) | ~234 |
| Full P-256 ECDSA verify | ~470,000 |

Compared to software-only P-256 (p256 crate): **9.1x faster**.

## Architecture

The inline verifies the algebraic identity `a*b + w*p = 2^256*w + c` where:
- `c = a*b mod q` (the 256-bit result)
- `w = floor(a*b/q)` (supplied as non-deterministic advice by the prover)
- `p = 2^256 - q` (the modular complement)

This is the same verification technique used by `jolt-inlines-secp256k1`, adapted for the P-256 prime structure.

## P-256 vs secp256k1

| Property | secp256k1 | P-256 |
|----------|:---------:|:-----:|
| Modular complement size | 1 limb (33 bits) | 4 limbs (224 bits) |
| GLV endomorphism | Yes (2x speedup) | No |
| Curve parameter a | 0 | -3 |
| ECDSA cycles | ~262,000 | ~470,000 |

The 1.8x cost difference comes from the larger modular complement (more MAC operations per inline) and the lack of GLV decomposition (256-bit scalars instead of 128-bit).

## Usage

### Guest (RISC-V target)

```toml
[dependencies]
jolt-inlines-p256 = { path = "..." }
```

```rust
use jolt_inlines_p256::{P256Fr, P256Point, ecdsa_verify, UnwrapOrSpoilProof};

#[jolt::provable]
fn verify_sig(z: [u64; 4], r: [u64; 4], s: [u64; 4], q: [u64; 8]) {
    let z = P256Fr::from_u64_arr(&z).unwrap_or_spoil_proof();
    let r = P256Fr::from_u64_arr(&r).unwrap_or_spoil_proof();
    let s = P256Fr::from_u64_arr(&s).unwrap_or_spoil_proof();
    let q = P256Point::from_u64_arr(&q).unwrap_or_spoil_proof();
    ecdsa_verify(z, r, s, q).unwrap_or_spoil_proof();
}
```

### Host (for inline registration)

```toml
[dependencies]
jolt-inlines-p256 = { path = "...", features = ["host"] }
```

```rust
extern crate jolt_inlines_p256; // forces auto-registration via #[ctor::ctor]
```

## License

MIT
