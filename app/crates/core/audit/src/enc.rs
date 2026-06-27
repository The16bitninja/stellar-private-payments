//! Rust mirror of the in-circuit `PoseidonAuditEncrypt` gadget, plus the
//! auditor-side decryption.
//!
//! Uses the project's Poseidon2 (`POSEIDON2_BN256_PARAMS_3/4`, taking the first
//! permutation lane) exactly as the circuit's `Poseidon2(2/3)` templates do, so
//! the witness reproduces the circuit's ciphertext bit-for-bit and the auditor
//! recovers the plaintext off-circuit. Domain separators 5/6/7 (KDF/keystream/
//! tag) continue the scheme's `1-4` (commitment/nullifier/keypair/signature).

use crate::babyjub;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::{BigInt, Sign};
use zkhash::{
    fields::bn256::FpBN256 as Scalar,
    poseidon2::{
        poseidon2::Poseidon2,
        poseidon2_instance_bn256::{POSEIDON2_BN256_PARAMS_3, POSEIDON2_BN256_PARAMS_4},
    },
};

/// Domain separator for the ECDH key-derivation hash.
pub const DOM_KDF: u64 = 5;
/// Domain separator for the keystream blocks.
pub const DOM_KS: u64 = 6;
/// Domain separator for the authentication tag.
pub const DOM_TAG: u64 = 7;

/// Poseidon2(2) with domain separation — `Poseidon2(POSEIDON2_BN256_PARAMS_3)`,
/// first lane.
fn hash2(a: Scalar, b: Scalar, dom: Scalar) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);
    h.permutation(&[a, b, dom])[0]
}

/// Poseidon2(3) with domain separation — `Poseidon2(POSEIDON2_BN256_PARAMS_4)`,
/// first lane.
fn hash3(a: Scalar, b: Scalar, c: Scalar, dom: Scalar) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_4);
    h.permutation(&[a, b, c, dom])[0]
}

/// `ark_bn254::Fr` -> zkhash `Scalar` (same BN254 scalar field, distinct types).
pub fn ark_to_scalar(f: Fr) -> Scalar {
    Scalar::from_le_bytes_mod_order(&f.into_bigint().to_bytes_le())
}

/// zkhash `Scalar` -> canonical non-negative big integer.
pub fn scalar_to_bigint(s: Scalar) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, &s.into_bigint().to_bytes_le())
}

/// Big integer -> zkhash `Scalar` (reduced mod p).
pub fn bigint_to_scalar(n: &BigInt) -> Scalar {
    let (_, bytes) = n.to_bytes_le();
    Scalar::from_le_bytes_mod_order(&bytes)
}

/// The shared secret coordinates as field scalars, from a Baby JubJub point.
pub fn shared_secret_scalars(point: babyjub::Point) -> (Scalar, Scalar) {
    (ark_to_scalar(point.0), ark_to_scalar(point.1))
}

/// Domain separator for note commitments (`Poseidon2` leaf, scheme constant 1).
pub const DOM_COMMITMENT: u64 = 1;
/// Domain separator for keypair derivation (`Keypair` template, constant 3).
pub const DOM_KEYPAIR: u64 = 3;

/// Derive the note public key from a private key — `Poseidon2(privKey, 0; dom 3)`,
/// matching the circuit's `Keypair` template.
pub fn derive_public_key(private_key: Scalar) -> Scalar {
    hash2(private_key, Scalar::from(0u64), Scalar::from(DOM_KEYPAIR))
}

/// Recompute a note commitment — `Poseidon2(amount, publicKey, blinding; dom 1)`,
/// matching the circuit / pool commitment derivation.
pub fn commitment(amount: Scalar, public_key: Scalar, blinding: Scalar) -> Scalar {
    hash3(amount, public_key, blinding, Scalar::from(DOM_COMMITMENT))
}

/// Poseidon2 keystream + tag encryption — identical to the circuit gadget.
///
/// `plaintext = [amount, blinding, publicKey]`, `s` is the shared-secret point
/// coordinates, `nonce` is the disclosure's `extContextHash`. Returns the
/// ciphertext `[c0, c1, c2, tag]`.
pub fn encrypt(plaintext: [Scalar; 3], s: (Scalar, Scalar), nonce: Scalar) -> [Scalar; 4] {
    let kdf = hash3(s.0, s.1, nonce, Scalar::from(DOM_KDF));
    let k0 = hash2(kdf, Scalar::from(0u64), Scalar::from(DOM_KS));
    let k1 = hash2(kdf, Scalar::from(1u64), Scalar::from(DOM_KS));
    let k2 = hash2(kdf, Scalar::from(2u64), Scalar::from(DOM_KS));
    let c0 = plaintext[0] + k0;
    let c1 = plaintext[1] + k1;
    let c2 = plaintext[2] + k2;
    let t0 = hash3(kdf, c0, c1, Scalar::from(DOM_TAG));
    let tag = hash3(t0, c2, nonce, Scalar::from(DOM_TAG));
    [c0, c1, c2, tag]
}

/// Auditor-side decryption; returns the plaintext iff the tag authenticates.
pub fn decrypt(ciphertext: [Scalar; 4], s: (Scalar, Scalar), nonce: Scalar) -> Option<[Scalar; 3]> {
    let kdf = hash3(s.0, s.1, nonce, Scalar::from(DOM_KDF));
    let t0 = hash3(kdf, ciphertext[0], ciphertext[1], Scalar::from(DOM_TAG));
    let tag = hash3(t0, ciphertext[2], nonce, Scalar::from(DOM_TAG));
    if tag != ciphertext[3] {
        return None;
    }
    let k0 = hash2(kdf, Scalar::from(0u64), Scalar::from(DOM_KS));
    let k1 = hash2(kdf, Scalar::from(1u64), Scalar::from(DOM_KS));
    let k2 = hash2(kdf, Scalar::from(2u64), Scalar::from(DOM_KS));
    Some([ciphertext[0] - k0, ciphertext[1] - k1, ciphertext[2] - k2])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secret() -> (Scalar, Scalar) {
        let s = babyjub::pubkey(&BigInt::from(13579u64));
        shared_secret_scalars(s)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let pt = [Scalar::from(17u64), Scalar::from(5151u64), Scalar::from(123u64)];
        let s = sample_secret();
        let nonce = Scalar::from(0xC0FFEEu64);

        let ct = encrypt(pt, s, nonce);
        assert_eq!(decrypt(ct, s, nonce), Some(pt));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let pt = [Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let s = sample_secret();
        let nonce = Scalar::from(42u64);

        let mut ct = encrypt(pt, s, nonce);
        ct[0] += Scalar::from(1u64);
        assert_eq!(decrypt(ct, s, nonce), None);
    }

    #[test]
    fn wrong_secret_does_not_recover() {
        let pt = [Scalar::from(7u64), Scalar::from(8u64), Scalar::from(9u64)];
        let s = sample_secret();
        let nonce = Scalar::from(99u64);
        let ct = encrypt(pt, s, nonce);

        let wrong = (s.0 + Scalar::from(1u64), s.1);
        assert_ne!(decrypt(ct, wrong, nonce), Some(pt));
    }

    /// The whole point: the sender encrypts under `S = r·A_pub`, and the auditor
    /// — holding only `a` and the public `R` — decrypts under `S = a·R`. The two
    /// shared secrets must coincide (Baby JubJub ECDH) for recovery to succeed.
    #[test]
    fn ecdh_sender_and_auditor_agree() {
        let auditor_secret = BigInt::from(1234567890123456789u64);
        let ephemeral = BigInt::from(9876543210987654321u64);

        let a_pub = babyjub::pubkey(&auditor_secret); // A_pub = a·G
        let r_point = babyjub::pubkey(&ephemeral); // R = r·G

        let s_sender = babyjub::scalar_mul(&ephemeral, a_pub); // r·A_pub
        let s_auditor = babyjub::scalar_mul(&auditor_secret, r_point); // a·R
        assert_eq!(s_sender, s_auditor, "ECDH shared secrets must agree");

        let pt = [Scalar::from(17u64), Scalar::from(5151u64), Scalar::from(4242u64)];
        let nonce = Scalar::from(0xC0FFEEu64);

        let ct = encrypt(pt, shared_secret_scalars(s_sender), nonce);
        let recovered = decrypt(ct, shared_secret_scalars(s_auditor), nonce);
        assert_eq!(recovered, Some(pt), "auditor failed to recover plaintext");
    }
}
