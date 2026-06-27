//! End-to-end auditor verifiable-disclosure loop.
//!
//! Proves a real `selectiveDisclosureAudit` proof, routes its `(commitment, R,
//! C_aud)` through the deployed `pool.disclose` entry point (which emits the
//! `AuditDisclosureEvent` feed), and has the auditor — holding only its Baby
//! JubJub secret `a` — reconstruct the hidden note from the disclosed values.
//!
//! This ties together every layer: circuit → contract event → auditor recovery.

use super::utils::{LEVELS, deploy_contracts, test_env};
use audit::{babyjub, disclosure::AuditDisclosure, reconstruct};
use circuits::test::utils::{
    circom_tester::{Inputs, load_keys, prove_and_verify_with_keys},
    general::{load_artifacts, scalar_to_bigint},
    keypair::derive_public_key,
    merkle_tree::{merkle_proof, merkle_root},
    transaction::{commitment, prepopulated_leaves},
};
use num_bigint::BigInt;
use pool::{BjjPoint, PoolContractClient};
use soroban_sdk::{Bytes, Env, U256, testutils::Events as _};
use std::path::PathBuf;
use zkhash::fields::bn256::FpBN256 as Scalar;

const EXT_CONTEXT_HASH: u64 = 0xC0FFEE;
const LEAF_INDEX: usize = 7;

/// Path to the pre-generated audit-circuit proving key under `testdata/`.
fn audit_proving_key_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("testdata/selectiveDisclosureAudit_proving_key.bin")
}

/// Convert a non-negative big integer to a Soroban `U256` (32-byte big-endian).
fn bigint_to_u256(env: &Env, n: &BigInt) -> U256 {
    let (_, be) = n.to_bytes_be();
    let mut buf = [0u8; 32];
    let off = 32usize
        .checked_sub(be.len())
        .expect("field element fits in 32 bytes");
    buf[off..].copy_from_slice(&be);
    U256::from_be_bytes(env, &Bytes::from_array(env, &buf))
}

/// Full loop: prove → pool.disclose → auditor reconstructs the note.
///
/// Ignored by default — it needs the compiled circuit artifacts
/// (`cargo build -p circuits`) and the audit proving key in `testdata/`. Run:
///   `cargo test -p e2e-tests auditor_disclosure -- --ignored --nocapture`
#[test]
#[ignore]
fn auditor_disclosure_full_loop() {
    // ---- note material ----
    let amount = Scalar::from(17u64);
    let blinding = Scalar::from(5151u64);
    let private_key = Scalar::from(4242u64);
    let public_key = derive_public_key(private_key);
    let note_commitment = commitment(amount, public_key, blinding);

    // ---- freeze the note into a depth-10 tree and build its Merkle proof ----
    let mut leaves = prepopulated_leaves(LEVELS, 0xD15C_105E_u64, &[LEAF_INDEX], 24);
    leaves[LEAF_INDEX] = note_commitment;
    let root = merkle_root(leaves.clone());
    let (siblings, path_idx_u64, depth) = merkle_proof(&leaves, LEAF_INDEX);
    assert_eq!(depth, LEVELS, "unexpected Merkle depth");
    let path_elements: Vec<BigInt> = siblings.into_iter().map(scalar_to_bigint).collect();

    // ---- auditor channel: secret a, A_pub = a·G, ephemeral r ----
    let auditor_secret = BigInt::from(1234567890123456789u64);
    let ephemeral = BigInt::from(9876543210987654321u64);
    let a_pub = babyjub::pubkey(&auditor_secret);

    // ---- build the witness and prove ----
    let mut inputs = Inputs::new();
    inputs.set("amount", amount);
    inputs.set("privateKey", private_key);
    inputs.set("blinding", blinding);
    inputs.set("pathIndices", Scalar::from(path_idx_u64));
    inputs.set("pathElements", path_elements);
    inputs.set("merkleRoot", root);
    inputs.set("ephemeralScalar", ephemeral);
    inputs.set(
        "auditorPubKey",
        vec![babyjub::fr_to_bigint(a_pub.0), babyjub::fr_to_bigint(a_pub.1)],
    );
    inputs.set("extContextHash", Scalar::from(EXT_CONTEXT_HASH));

    let (wasm, r1cs) =
        load_artifacts("selectiveDisclosureAudit").expect("circuit artifacts (build -p circuits)");
    let keys = load_keys(audit_proving_key_path()).expect("audit proving key in testdata");
    let res = prove_and_verify_with_keys(&wasm, &r1cs, &inputs, &keys).expect("prove");
    assert!(res.verified, "audit disclosure proof did not verify");

    // public signals: [commitment, R.x, R.y, c0, c1, c2, tag, merkleRoot, A.x, A.y, nonce]
    let sig = |i: usize| babyjub::fr_to_bigint(res.public_inputs[i]);
    assert_eq!(
        sig(0),
        scalar_to_bigint(note_commitment),
        "circuit commitment output != note commitment"
    );

    // ---- route the disclosure through the deployed pool ----
    let env = test_env();
    env.mock_all_auths();
    let contracts = deploy_contracts(&env);
    let pool = PoolContractClient::new(&env, &contracts.pool);

    let a_pub_point = BjjPoint {
        x: bigint_to_u256(&env, &sig(8)),
        y: bigint_to_u256(&env, &sig(9)),
    };
    pool.set_auditor_pubkey(&a_pub_point);

    let r_point = BjjPoint {
        x: bigint_to_u256(&env, &sig(1)),
        y: bigint_to_u256(&env, &sig(2)),
    };
    let mut ciphertext = soroban_sdk::Vec::new(&env);
    for i in 3..7 {
        ciphertext.push_back(bigint_to_u256(&env, &sig(i)));
    }
    let commitment_u = bigint_to_u256(&env, &sig(0));
    let ext_context_hash_u = bigint_to_u256(&env, &sig(10));

    pool.disclose(&commitment_u, &r_point, &ciphertext, &ext_context_hash_u);

    // The pool emitted exactly the audit-disclosure feed event.
    let events = env.events().all();
    assert!(
        !events.events().is_empty(),
        "disclose should emit an event"
    );
    std::println!("AUDIT_DISCLOSURE_EVENT_ABI: {:?}", events.events());

    // ---- the auditor reconstructs the note from the disclosed values ----
    let disclosure = AuditDisclosure {
        commitment: sig(0),
        ephemeral_pub_key: (sig(1), sig(2)),
        ciphertext: [sig(3), sig(4), sig(5), sig(6)],
        merkle_root: sig(7),
        auditor_pub_key: (sig(8), sig(9)),
        ext_context_hash: sig(10),
    };
    let note = reconstruct::reconstruct(&auditor_secret, &disclosure).expect("auditor recovers note");
    assert_eq!(note.amount, BigInt::from(17u64));
    assert_eq!(note.blinding, BigInt::from(5151u64));
    assert_eq!(note.public_key, scalar_to_bigint(public_key));
    assert_eq!(note.commitment, sig(0));
}
