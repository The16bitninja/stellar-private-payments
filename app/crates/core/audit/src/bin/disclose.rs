//! Lumenveil disclosure producer (sender side).
//!
//! Builds a note's `selectiveDisclosureAudit` witness, proves it via
//! [`audit::wiring::prove_audit_disclosure`], and writes the on-chain
//! disclosure record `(commitment, R, C_aud, extContextHash)` plus the proof.
//! The record is what `auditor/disclose.mjs` submits to `pool.disclose`; the
//! proof is what an auditor verifies off-chain against the pinned key.
//!
//! Demo parameters are synthetic but self-consistent: the auditor secret whose
//! `A_pub` is used here is emitted as `auditor_secret_demo` so the whole loop
//! (disclose → scan → reconstruct) is runnable end to end.
//!
//! Usage: lumenveil-disclose [out.json]   (needs `cargo build -p circuits`)

use anyhow::{Context, Result};
use audit::disclosure::AuditWitnessInputs;
use audit::record::DisclosureRecord;
use audit::wiring::prove_audit_disclosure;
use audit::babyjub;
use num_bigint::{BigInt, Sign};
use prover::crypto::{compute_commitment, derive_public_key, zero_leaf};
use prover::merkle::MerklePrefixTree;
use std::path::{Path, PathBuf};
use types::{Field, U256};

const LEVELS: u32 = 10;
const LEAF_INDEX: u32 = 7;
const EXT_CONTEXT_HASH: u64 = 0xC0FFEE;

fn field_from_u64(v: u64) -> Field {
    Field(U256::from(v))
}

fn field_to_bigint(f: &Field) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, &f.to_le_bytes())
}

fn field_from_le_vec(bytes: Vec<u8>) -> Result<Field> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("field element must be 32 bytes"))?;
    Field::try_from_le_bytes(arr).context("non-canonical field element")
}

fn zero_leaf_field() -> Result<Field> {
    let mut be = zero_leaf();
    be.reverse();
    field_from_le_vec(be)
}

fn workspace_root() -> Result<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .context("workspace root above app/crates/core/audit")?
        .to_path_buf())
}

fn main() -> Result<()> {
    let out = std::env::args().nth(1).unwrap_or_else(|| "disclosure.json".to_string());

    // ---- note material (synthetic but self-consistent) ----
    let amount = field_from_u64(17);
    let blinding = field_from_u64(5151);
    let private_key = field_from_u64(4242);
    let public_key_le = derive_public_key(&private_key.to_le_bytes())?;
    let commitment_le =
        compute_commitment(&amount.to_le_bytes(), &public_key_le, &blinding.to_le_bytes())?;
    let commitment = field_from_le_vec(commitment_le)?;

    // ---- freeze the note into a depth-10 tree and build its Merkle proof ----
    let idx = usize::try_from(LEAF_INDEX).expect("index fits usize");
    let mut leaves = vec![zero_leaf_field()?; idx];
    leaves.push(commitment);
    let tree = MerklePrefixTree::new(LEVELS, &leaves)?.into_built();
    let root = tree.root()?;
    let merkle_proof = tree.proof(LEAF_INDEX)?;

    // ---- auditor channel: the sender uses the pinned A_pub (a is the auditor's) ----
    let auditor_secret = BigInt::from(1234567890123456789u64);
    let ephemeral = BigInt::from(9876543210987654321u64);
    let a_pub = babyjub::pubkey(&auditor_secret);

    let inputs = AuditWitnessInputs {
        amount: field_to_bigint(&amount),
        private_key: field_to_bigint(&private_key),
        blinding: field_to_bigint(&blinding),
        path_indices: field_to_bigint(&merkle_proof.path_indices()),
        path_elements: merkle_proof.path_elements().iter().map(field_to_bigint).collect(),
        merkle_root: field_to_bigint(&root),
        ephemeral_scalar: ephemeral,
        auditor_pub_key: (babyjub::fr_to_bigint(a_pub.0), babyjub::fr_to_bigint(a_pub.1)),
        ext_context_hash: BigInt::from(EXT_CONTEXT_HASH),
    };

    // ---- prove and emit the submission record ----
    let root_dir = workspace_root()?;
    let wasm = std::fs::read(
        root_dir.join("target/circuits-artifacts/debug/selectiveDisclosureAudit.wasm"),
    )
    .context("circuit wasm (run `cargo build -p circuits`)")?;
    let r1cs = std::fs::read(
        root_dir.join("target/circuits-artifacts/debug/selectiveDisclosureAudit.r1cs"),
    )
    .context("circuit r1cs (run `cargo build -p circuits`)")?;
    let pk = std::fs::read(root_dir.join("testdata/selectiveDisclosureAudit_proving_key.bin"))
        .context("audit proving key in testdata")?;

    let (disclosure, proof) = prove_audit_disclosure(&wasm, &r1cs, &pk, &inputs)?;
    let record = DisclosureRecord::from_disclosure(&disclosure);

    let payload = serde_json::json!({
        "record": record,
        "proof_hex": hex::encode(&proof),
        "auditor_secret_demo": auditor_secret.to_string(),
    });
    std::fs::write(&out, serde_json::to_string_pretty(&payload)?)
        .with_context(|| format!("writing {out}"))?;

    println!("Proved disclosure for note amount=17");
    println!("  commitment: {}", record.commitment);
    println!("  wrote record + proof to {out}");
    Ok(())
}
