//! Prover wiring for the `selectiveDisclosureAudit` circuit.
//!
//! Bridges the typed witness inputs to the production witness calculator and
//! Groth16 prover, returning the parsed [`AuditDisclosure`] (the `(R, C_aud)`
//! feed) alongside the compressed proof. Gated behind the `prover` feature so
//! the pure crypto library and the auditor binary stay free of the heavy
//! witness/prover dependencies.

use crate::disclosure::{AuditDisclosure, AuditWitnessInputs, parse_public_signals};
use anyhow::{Result, anyhow};
use prover::prover::Prover;
use witness::WitnessCalculator;

/// Build the witness for an audit disclosure, prove it, and parse the public
/// signals into a typed [`AuditDisclosure`].
///
/// Returns the disclosure (commitment, ephemeral key `R`, ciphertext `C_aud`,
/// and the echoed public inputs) together with the compressed Groth16 proof.
/// Errors if witness generation, proving, or local verification fails.
pub fn prove_audit_disclosure(
    circuit_wasm: &[u8],
    r1cs_bytes: &[u8],
    proving_key_bytes: &[u8],
    inputs: &AuditWitnessInputs,
) -> Result<(AuditDisclosure, Vec<u8>)> {
    let mut calculator = WitnessCalculator::new(circuit_wasm, r1cs_bytes)?;
    let witness = calculator.compute_witness(&inputs.to_inputs_json())?;

    let prover = Prover::new(proving_key_bytes, r1cs_bytes)?;
    let proof = prover.prove_bytes(&witness)?;
    let public_inputs = prover.extract_public_inputs(&witness)?;

    if !prover.verify(&proof, &public_inputs)? {
        return Err(anyhow!("audit disclosure proof did not verify"));
    }

    let disclosure = parse_public_signals(&public_inputs)?;
    Ok((disclosure, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{babyjub, reconstruct};
    use num_bigint::{BigInt, Sign};
    use prover::crypto::{compute_commitment, derive_public_key, zero_leaf};
    use prover::merkle::MerklePrefixTree;
    use std::path::{Path, PathBuf};
    use types::{Field, U256};

    const LEVELS: u32 = 10;
    const LEAF_INDEX: u32 = 7;
    const EXT_CONTEXT_HASH: u64 = 0xC0FFEE;

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("workspace root above app/crates/core/audit")
            .to_path_buf()
    }

    fn field_from_u64(v: u64) -> Field {
        Field(U256::from(v))
    }

    fn field_to_bigint(f: &Field) -> BigInt {
        BigInt::from_bytes_le(Sign::Plus, &f.to_le_bytes())
    }

    fn field_from_le_vec(bytes: Vec<u8>) -> Field {
        let arr: [u8; 32] = bytes.try_into().expect("field element is 32 bytes");
        Field::try_from_le_bytes(arr).expect("canonical field element")
    }

    fn zero_leaf_field() -> Field {
        let mut be = zero_leaf();
        be.reverse();
        field_from_le_vec(be)
    }

    /// End-to-end: build a real note, prove the audit disclosure through the
    /// production witness+prover stack, and have the auditor recover the note
    /// from the parsed `(R, C_aud)`.
    ///
    /// Ignored by default: it requires the compiled circuit artifacts
    /// (`cargo build -p circuits`) and the generated proving key under
    /// `testdata/`. Run with:
    ///   `cargo test -p audit --features prover -- --ignored`
    #[test]
    #[ignore]
    fn prove_and_auditor_recovers_note() -> Result<()> {
        let root = workspace_root();
        let wasm = std::fs::read(
            root.join("target/circuits-artifacts/debug/selectiveDisclosureAudit.wasm"),
        )
        .expect("circuit wasm (run `cargo build -p circuits`)");
        let r1cs = std::fs::read(
            root.join("target/circuits-artifacts/debug/selectiveDisclosureAudit.r1cs"),
        )
        .expect("circuit r1cs (run `cargo build -p circuits`)");
        let pk = std::fs::read(root.join("testdata/selectiveDisclosureAudit_proving_key.bin"))
            .expect("proving key in testdata");

        // ----- note material -----
        let amount = field_from_u64(17);
        let blinding = field_from_u64(5151);
        let private_key = field_from_u64(4242);

        let public_key_le = derive_public_key(&private_key.to_le_bytes())?;
        let commitment_le =
            compute_commitment(&amount.to_le_bytes(), &public_key_le, &blinding.to_le_bytes())?;
        let commitment = field_from_le_vec(commitment_le);

        // ----- freeze the note into a depth-10 tree at LEAF_INDEX -----
        let idx = usize::try_from(LEAF_INDEX).expect("index fits usize");
        let mut leaves = vec![zero_leaf_field(); idx];
        leaves.push(commitment);
        let tree = MerklePrefixTree::new(LEVELS, &leaves)?.into_built();
        let merkle_root = tree.root()?;
        let merkle_proof = tree.proof(LEAF_INDEX)?;

        // ----- auditor channel: a, A_pub = a·G, ephemeral r -----
        let auditor_secret = BigInt::from(1234567890123456789u64);
        let ephemeral = BigInt::from(9876543210987654321u64);
        let a_pub = babyjub::pubkey(&auditor_secret);

        let inputs = AuditWitnessInputs {
            amount: field_to_bigint(&amount),
            private_key: field_to_bigint(&private_key),
            blinding: field_to_bigint(&blinding),
            path_indices: field_to_bigint(&merkle_proof.path_indices()),
            path_elements: merkle_proof
                .path_elements()
                .iter()
                .map(field_to_bigint)
                .collect(),
            merkle_root: field_to_bigint(&merkle_root),
            ephemeral_scalar: ephemeral,
            auditor_pub_key: (babyjub::fr_to_bigint(a_pub.0), babyjub::fr_to_bigint(a_pub.1)),
            ext_context_hash: BigInt::from(EXT_CONTEXT_HASH),
        };

        // ----- prove (production stack) and parse the disclosure -----
        let (disclosure, proof) = prove_audit_disclosure(&wasm, &r1cs, &pk, &inputs)?;
        assert!(!proof.is_empty(), "expected a non-empty proof");
        assert_eq!(
            disclosure.commitment,
            field_to_bigint(&commitment),
            "circuit commitment output != note commitment"
        );

        // ----- the auditor, holding only `a`, recovers the hidden note -----
        let note = reconstruct::reconstruct(&auditor_secret, &disclosure)?;
        assert_eq!(note.amount, BigInt::from(17u64));
        assert_eq!(note.blinding, BigInt::from(5151u64));
        assert_eq!(note.commitment, disclosure.commitment);
        Ok(())
    }
}
