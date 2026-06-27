//! Minimal, dependency-free Baby JubJub (the curve circomlib embeds in BN254's
//! scalar field) over [`ark_bn254::Fr`].
//!
//! Mirrors circomlib's `BabyPbk` / `EscalarMulAny` so the app can reproduce the
//! in-circuit ECDH bit-for-bit: twisted Edwards `a·x² + y² = 1 + d·x²·y²` with
//! `a = 168700`, `d = 168696`, and the canonical prime-order generator `BASE8`.
//! This is the proven Day-2 construction, promoted from the circuit test into a
//! reusable library used by both the prover wiring and the auditor tool.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use num_bigint::{BigInt, Sign};
use std::str::FromStr;

/// A Baby JubJub point in affine `(x, y)` coordinates.
pub type Point = (Fr, Fr);

fn a() -> Fr {
    Fr::from(168700u64)
}

fn d() -> Fr {
    Fr::from(168696u64)
}

/// The order-`l` subgroup generator used by circomlib's `BabyPbk`.
pub fn base8() -> Point {
    (
        Fr::from_str(
            "5299619240641551281634865583518297030282874472190772894086521144482721001553",
        )
        .expect("valid base8.x"),
        Fr::from_str(
            "16950150798460657717958625567821834550301663161624707787222815936182638968203",
        )
        .expect("valid base8.y"),
    )
}

/// The identity element `(0, 1)`.
pub fn identity() -> Point {
    (Fr::zero(), Fr::one())
}

/// Twisted Edwards addition (complete on this curve).
pub fn add(p: Point, q: Point) -> Point {
    let (x1, y1) = p;
    let (x2, y2) = q;
    let x1x2 = x1 * x2;
    let y1y2 = y1 * y2;
    let dxy = d() * x1x2 * y1y2;
    let x3 = (x1 * y2 + y1 * x2) * (Fr::one() + dxy).inverse().expect("nonzero denominator");
    let y3 = (y1y2 - a() * x1x2) * (Fr::one() - dxy).inverse().expect("nonzero denominator");
    (x3, y3)
}

/// `k · p` via double-and-add over the literal LE bits of `k` — identical to
/// what circomlib's `EscalarMul*` computes for a 253-bit scalar.
pub fn scalar_mul(k: &BigInt, p: Point) -> Point {
    let mut result = identity();
    let mut addend = p;
    let mut kk = k.clone();
    let zero = BigInt::from(0u8);
    let two = BigInt::from(2u8);
    let one = BigInt::from(1u8);
    while kk > zero {
        if &kk % &two == one {
            result = add(result, addend);
        }
        addend = add(addend, addend);
        kk /= &two;
    }
    result
}

/// `r · BASE8` — the Baby JubJub public key for scalar `r` (circom `BabyPbk`).
pub fn pubkey(r: &BigInt) -> Point {
    scalar_mul(r, base8())
}

/// Convert a field element to its canonical non-negative big integer.
pub fn fr_to_bigint(f: Fr) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, &f.into_bigint().to_bytes_le())
}

/// Convert a non-negative big integer to a field element (reduced mod p).
pub fn bigint_to_fr(n: &BigInt) -> Fr {
    let (_, bytes) = n.to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on_curve(p: Point) -> bool {
        // a·x² + y² == 1 + d·x²·y²
        let (x, y) = p;
        let x2 = x * x;
        let y2 = y * y;
        a() * x2 + y2 == Fr::one() + d() * x2 * y2
    }

    #[test]
    fn base8_is_on_curve() {
        assert!(on_curve(base8()));
    }

    #[test]
    fn identity_is_neutral() {
        let g = base8();
        assert_eq!(add(g, identity()), g);
    }

    #[test]
    fn pubkey_one_is_base8() {
        assert_eq!(pubkey(&BigInt::from(1u8)), base8());
    }

    #[test]
    fn scalar_mul_two_equals_double() {
        let g = base8();
        assert_eq!(scalar_mul(&BigInt::from(2u8), g), add(g, g));
    }

    #[test]
    fn addition_is_commutative() {
        let g = base8();
        let g2 = add(g, g);
        assert_eq!(add(g, g2), add(g2, g));
    }

    #[test]
    fn scalar_products_stay_on_curve() {
        let p = pubkey(&BigInt::from(1234567890123456789u64));
        assert!(on_curve(p));
    }

    #[test]
    fn bigint_fr_roundtrip() {
        let n = BigInt::from(1234567890123456789u64);
        assert_eq!(fr_to_bigint(bigint_to_fr(&n)), n);
    }
}
