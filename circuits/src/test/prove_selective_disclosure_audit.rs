/// Minimal, dependency-free Baby JubJub (the curve circomlib embeds in BN254's
/// scalar field) over `ark_bn254::Fr`. Mirrors circomlib's `BabyPbk` /
/// `EscalarMulAny` so the Rust witness can reproduce the in-circuit ECDH:
/// twisted Edwards `a·x² + y² = 1 + d·x²·y²` with `a = 168700`, `d = 168696`,
/// and the canonical prime-order generator `BASE8`.
#[cfg(test)]
mod babyjub {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
    use num_bigint::{BigInt, Sign};
    use std::str::FromStr;

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
            .unwrap(),
            Fr::from_str(
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            )
            .unwrap(),
        )
    }

    fn identity() -> Point {
        (Fr::zero(), Fr::one())
    }

    /// Twisted Edwards addition (complete on this curve).
    pub fn add(p: Point, q: Point) -> Point {
        let (x1, y1) = p;
        let (x2, y2) = q;
        let x1x2 = x1 * x2;
        let y1y2 = y1 * y2;
        let dxy = d() * x1x2 * y1y2;
        let x3 = (x1 * y2 + y1 * x2) * (Fr::one() + dxy).inverse().unwrap();
        let y3 = (y1y2 - a() * x1x2) * (Fr::one() - dxy).inverse().unwrap();
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

    pub fn fr_to_bigint(f: Fr) -> BigInt {
        BigInt::from_bytes_le(Sign::Plus, &f.into_bigint().to_bytes_le())
    }
}

/// Rust mirror of the in-circuit `PoseidonAuditEncrypt` gadget, plus the
/// auditor-side decryption. Uses the project's `poseidon2_hash2/3` (which match
/// the circom `Poseidon2(n)` templates) so the witness reproduces the circuit's
/// ciphertext exactly, and the auditor recovers the plaintext off-circuit.
#[cfg(test)]
mod audit_enc {
    use super::babyjub;
    use crate::test::utils::general::{poseidon2_hash2, poseidon2_hash3};
    use num_bigint::BigInt;
    use std::str::FromStr;
    use zkhash::fields::bn256::FpBN256 as Scalar;

    pub const DOM_KDF: u64 = 5;
    pub const DOM_KS: u64 = 6;
    pub const DOM_TAG: u64 = 7;

    /// Fixed auditor Baby JubJub secret `a` for the tests.
    pub fn auditor_secret() -> BigInt {
        BigInt::parse_bytes(b"1234567890123456789", 10).unwrap()
    }

    /// Auditor public key `A_pub = a·G` (Baby JubJub), as field coordinates.
    pub fn auditor_pubkey() -> babyjub::Point {
        babyjub::pubkey(&auditor_secret())
    }

    /// `ark_bn254::Fr` -> zkhash `Scalar` (same BN254 scalar field, distinct
    /// Rust types), routed through the canonical decimal representation.
    pub fn ark_to_scalar(f: ark_bn254::Fr) -> Scalar {
        Scalar::from_str(&babyjub::fr_to_bigint(f).to_string()).expect("field element")
    }

    fn dom(x: u64) -> Scalar {
        Scalar::from(x)
    }

    /// Poseidon2 keystream + tag encryption — identical to the circuit gadget.
    pub fn encrypt(plaintext: [Scalar; 3], s: (Scalar, Scalar), nonce: Scalar) -> [Scalar; 4] {
        let kdf = poseidon2_hash3(s.0, s.1, nonce, Some(dom(DOM_KDF)));
        let k0 = poseidon2_hash2(kdf, Scalar::from(0u64), Some(dom(DOM_KS)));
        let k1 = poseidon2_hash2(kdf, Scalar::from(1u64), Some(dom(DOM_KS)));
        let k2 = poseidon2_hash2(kdf, Scalar::from(2u64), Some(dom(DOM_KS)));
        let c0 = plaintext[0] + k0;
        let c1 = plaintext[1] + k1;
        let c2 = plaintext[2] + k2;
        let t0 = poseidon2_hash3(kdf, c0, c1, Some(dom(DOM_TAG)));
        let tag = poseidon2_hash3(t0, c2, nonce, Some(dom(DOM_TAG)));
        [c0, c1, c2, tag]
    }

    /// Auditor-side decryption; returns the plaintext iff the tag authenticates.
    pub fn decrypt(
        ciphertext: [Scalar; 4],
        s: (Scalar, Scalar),
        nonce: Scalar,
    ) -> Option<[Scalar; 3]> {
        let kdf = poseidon2_hash3(s.0, s.1, nonce, Some(dom(DOM_KDF)));
        let t0 = poseidon2_hash3(kdf, ciphertext[0], ciphertext[1], Some(dom(DOM_TAG)));
        let tag = poseidon2_hash3(t0, ciphertext[2], nonce, Some(dom(DOM_TAG)));
        if tag != ciphertext[3] {
            return None;
        }
        let k0 = poseidon2_hash2(kdf, Scalar::from(0u64), Some(dom(DOM_KS)));
        let k1 = poseidon2_hash2(kdf, Scalar::from(1u64), Some(dom(DOM_KS)));
        let k2 = poseidon2_hash2(kdf, Scalar::from(2u64), Some(dom(DOM_KS)));
        Some([ciphertext[0] - k0, ciphertext[1] - k1, ciphertext[2] - k2])
    }
}

#[cfg(test)]
mod tests {
    use super::audit_enc;
    use super::babyjub;
    use crate::test::utils::{
        circom_tester::{CircuitKeys, Inputs, generate_keys, prove_and_verify_with_keys},
        general::{load_artifacts, scalar_to_bigint},
        keypair::derive_public_key,
        merkle_tree::{merkle_proof, merkle_root},
        transaction::{commitment, prepopulated_leaves},
    };
    use anyhow::{Context, Result};
    use num_bigint::BigInt;
    use std::{
        panic::{self, AssertUnwindSafe},
        path::Path,
    };
    use zkhash::fields::bn256::FpBN256 as Scalar;

    const EXT_CONTEXT_HASH: u64 = 0xC0FFEE_u64;

    /// Auditor-channel ephemeral scalar `r` (< 2^253) reused across the tests.
    fn sample_ephemeral_scalar() -> BigInt {
        BigInt::parse_bytes(b"9876543210987654321098765432109876543210", 10).unwrap()
    }

    /// `true` iff the prover produced a verifying proof. A returned `Err`, a
    /// `verified == false`, or a panic from the WASM witness calculator all
    /// count as rejection, so negative tests can assert uniformly.
    fn proof_verifies(
        wasm: impl AsRef<Path>,
        r1cs: impl AsRef<Path>,
        inputs: &Inputs,
        keys: &CircuitKeys,
    ) -> bool {
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            prove_and_verify_with_keys(wasm.as_ref(), r1cs.as_ref(), inputs, keys)
        }));
        matches!(outcome, Ok(Ok(ref res)) if res.verified)
    }

    const LEVELS: usize = 10;

    /// Note material for a single auditor-disclosure proof.
    struct DisclosureNote {
        leaf_index: usize,
        priv_key: Scalar,
        blinding: Scalar,
        amount: Scalar,
    }

    fn sample_note(leaf_index: usize) -> DisclosureNote {
        DisclosureNote {
            leaf_index,
            priv_key: Scalar::from(4242u64),
            blinding: Scalar::from(5151u64),
            amount: Scalar::from(17u64),
        }
    }

    fn sample_leaves(note: &DisclosureNote) -> Vec<Scalar> {
        prepopulated_leaves(LEVELS, 0xD15C_105E_u64, &[note.leaf_index], 24)
    }

    /// Builds the witness for the disclosed note: recompute its commitment,
    /// freeze it into the tree at `leaf_index`, and produce the Merkle proof.
    fn build_inputs(note: &DisclosureNote, leaves: &[Scalar]) -> Result<Inputs> {
        let pub_key = derive_public_key(note.priv_key);
        let note_commitment = commitment(note.amount, pub_key, note.blinding);

        let mut frozen = leaves.to_vec();
        frozen[note.leaf_index] = note_commitment;

        let root = merkle_root(frozen.clone());
        let (siblings, path_idx_u64, depth) = merkle_proof(&frozen, note.leaf_index);
        assert_eq!(
            depth, LEVELS,
            "unexpected Merkle depth: expected {LEVELS}, got {depth}"
        );

        let path_elements: Vec<BigInt> = siblings.into_iter().map(scalar_to_bigint).collect();

        let mut inputs = Inputs::new();
        inputs.set("amount", note.amount);
        inputs.set("privateKey", note.priv_key);
        inputs.set("blinding", note.blinding);
        inputs.set("pathIndices", Scalar::from(path_idx_u64));
        inputs.set("pathElements", path_elements);
        inputs.set("merkleRoot", root);
        inputs.set("ephemeralScalar", sample_ephemeral_scalar());

        // auditor channel: pin A_pub (public), bind ciphertext to extContextHash
        let a_pub = audit_enc::auditor_pubkey();
        inputs.set(
            "auditorPubKey",
            vec![babyjub::fr_to_bigint(a_pub.0), babyjub::fr_to_bigint(a_pub.1)],
        );
        inputs.set("extContextHash", Scalar::from(EXT_CONTEXT_HASH));
        Ok(inputs)
    }

    /// Shared secret S = r·A_pub as zkhash field coords (auditor channel).
    fn shared_secret() -> (Scalar, Scalar) {
        let s = babyjub::scalar_mul(&sample_ephemeral_scalar(), audit_enc::auditor_pubkey());
        (audit_enc::ark_to_scalar(s.0), audit_enc::ark_to_scalar(s.1))
    }

    #[test]
    #[ignore]
    fn test_audit_disclosure_valid_note() -> Result<()> {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosureAudit")
            .expect("Cannot find selectiveDisclosureAudit artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(7);
        let leaves = sample_leaves(&note);
        let inputs = build_inputs(&note, &leaves)?;
        let res = prove_and_verify_with_keys(&wasm, &r1cs, &inputs, &keys)
            .context("prove_and_verify failed")?;
        assert!(res.verified, "audit disclosure proof did not verify");
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_audit_disclosure_ephemeral_pubkey_matches_ecdh() -> Result<()> {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosureAudit")
            .expect("Cannot find selectiveDisclosureAudit artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(11);
        let leaves = sample_leaves(&note);
        let inputs = build_inputs(&note, &leaves)?;
        let res = prove_and_verify_with_keys(&wasm, &r1cs, &inputs, &keys)
            .context("prove_and_verify failed")?;
        assert!(res.verified, "audit disclosure proof did not verify");

        // The circuit must output R = r·G on Baby JubJub. Public signals are
        // ordered outputs-then-public-inputs: [commitment, R.x, R.y, merkleRoot].
        let expected_r = babyjub::pubkey(&sample_ephemeral_scalar());
        assert_eq!(
            res.public_inputs[1], expected_r.0,
            "ephemeralPubKey.x != r·G; public_inputs={:?}",
            res.public_inputs
        );
        assert_eq!(
            res.public_inputs[2], expected_r.1,
            "ephemeralPubKey.y != r·G"
        );
        Ok(())
    }

    /// Fast, proof-free check that the Rust encrypt/decrypt mirror is a correct
    /// authenticated cipher (round-trips, and rejects a tampered tag).
    #[test]
    fn test_audit_encrypt_decrypt_roundtrip() {
        let plaintext = [Scalar::from(17u64), Scalar::from(5151u64), Scalar::from(123u64)];
        let s = shared_secret();
        let nonce = Scalar::from(EXT_CONTEXT_HASH);

        let ct = audit_enc::encrypt(plaintext, s, nonce);
        let recovered = audit_enc::decrypt(ct, s, nonce).expect("tag must authenticate");
        assert_eq!(recovered, plaintext, "decrypt did not recover plaintext");

        // A tampered ciphertext must fail the tag check.
        let mut tampered = ct;
        tampered[0] += Scalar::from(1u64);
        assert!(
            audit_enc::decrypt(tampered, s, nonce).is_none(),
            "tampered ciphertext unexpectedly authenticated"
        );

        // The wrong shared secret must not recover the plaintext.
        let wrong = (s.0 + Scalar::from(1u64), s.1);
        assert_ne!(
            audit_enc::decrypt(ct, wrong, nonce),
            Some(plaintext),
            "wrong key unexpectedly recovered plaintext"
        );
    }

    /// End-to-end: a valid proof's ciphertext output decrypts (auditor-side)
    /// back to the note's (amount, blinding, publicKey), which recomputes the
    /// proof's committed value.
    #[test]
    #[ignore]
    fn test_audit_disclosure_ciphertext_decrypts() -> Result<()> {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosureAudit")
            .expect("Cannot find selectiveDisclosureAudit artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(9);
        let leaves = sample_leaves(&note);
        let inputs = build_inputs(&note, &leaves)?;
        let res = prove_and_verify_with_keys(&wasm, &r1cs, &inputs, &keys)
            .context("prove_and_verify failed")?;
        assert!(res.verified, "audit disclosure proof did not verify");

        // Public signals: [commitment, R.x, R.y, c0, c1, c2, tag, merkleRoot, A.x, A.y, nonce]
        let pub_key = derive_public_key(note.priv_key);
        let plaintext = [note.amount, note.blinding, pub_key];
        let s = shared_secret();
        let nonce = Scalar::from(EXT_CONTEXT_HASH);

        // (a) the circuit's ciphertext equals the Rust gadget's output
        let expected = audit_enc::encrypt(plaintext, s, nonce);
        for i in 0..4 {
            assert_eq!(
                scalar_to_bigint(expected[i]),
                babyjub::fr_to_bigint(res.public_inputs[3 + i]),
                "ciphertext[{i}] mismatch between circuit and Rust gadget"
            );
        }

        // (b) the auditor decrypts the circuit's actual ciphertext output
        let circuit_ct = [
            audit_enc::ark_to_scalar(res.public_inputs[3]),
            audit_enc::ark_to_scalar(res.public_inputs[4]),
            audit_enc::ark_to_scalar(res.public_inputs[5]),
            audit_enc::ark_to_scalar(res.public_inputs[6]),
        ];
        let recovered = audit_enc::decrypt(circuit_ct, s, nonce).expect("auditor tag check");
        assert_eq!(recovered, plaintext, "auditor failed to recover the note");

        // (c) the recovered note recomputes the proof's committed value
        // commitment = Poseidon2(amount, publicKey, blinding; dom 0x01)
        let recomputed = commitment(recovered[0], recovered[2], recovered[1]);
        assert_eq!(
            scalar_to_bigint(recomputed),
            babyjub::fr_to_bigint(res.public_inputs[0]),
            "recovered note does not match the committed value"
        );
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_audit_disclosure_wrong_private_key_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosureAudit")
            .expect("Cannot find selectiveDisclosureAudit artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(14);
        let leaves = sample_leaves(&note);
        let mut inputs = build_inputs(&note, &leaves).expect("witness inputs");
        inputs.set("privateKey", Scalar::from(9999u64));

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong private key case unexpectedly verified; expected rejection"
        );
    }
}
