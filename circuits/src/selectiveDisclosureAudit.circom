pragma circom 2.2.2;

// =============================================================================
// Lumenveil — selectiveDisclosureAudit.circom
// -----------------------------------------------------------------------------
// NEW (Lumenveil). Derivative of upstream `selectiveDisclosure.circom`
// (Nethermind stellar-private-payments, Apache-2.0).
//
// PURPOSE: prove ownership of a pool note AND output a *verifiable* encryption
// of its value to a designated auditor key. A valid proof guarantees the
// auditor (holder of the Baby JubJub secret `a`) can decrypt the true
// (amount, blinding, publicKey) and recompute the committed value — a malicious
// prover cannot bind a poisoned auditor ciphertext, which upstream's plain
// extDataHash binding does NOT guarantee.
//
// Standalone circuit ("Route 2"): it does NOT touch policy_tx, so the deployed
// pool/verifier need no consensus-path changes. `levels` MUST match the
// deployed pool Merkle depth (10 for policy_tx_2_2).
// =============================================================================

include "./keypair.circom";            // Keypair(): publicKey = Poseidon2(privateKey, 0; dom 0x03)
include "./merkleProof.circom";        // MerkleProof(levels)
include "./poseidon2/poseidon2_hash.circom";
include "./circomlib/circuits/babyjub.circom";        // BabyPbk(): R = in·BASE8
include "./circomlib/circuits/escalarmulany.circom";  // EscalarMulAny(n): S = r·A_pub
include "./circomlib/circuits/bitify.circom";          // Num2Bits

// -----------------------------------------------------------------------------
// Verifiable encryption of a 3-element note plaintext to the auditor, keyed by
// the ECDH shared secret S = (Sx, Sy). Poseidon2 is used in three roles, each
// with its own domain separation (1..4 are reserved by upstream for
// commitment/nullifier/keypair/signature):
//   * KDF  (dom 5): derive a per-disclosure key from (Sx, Sy, nonce)
//   * KS   (dom 6): keystream k_i = Poseidon2(kdf, i); c_i = p_i + k_i
//   * TAG  (dom 7): authentication tag chained over (kdf, ciphertext, nonce)
// The auth tag binds the ciphertext to the key and nonce so the auditor can
// detect tampering off-circuit; the Groth16 proof already binds it to the
// committed note on-circuit.
// -----------------------------------------------------------------------------
template PoseidonAuditEncrypt() {
    signal input plaintext[3];   // [amount, blinding, publicKey]
    signal input sharedKey[2];   // (Sx, Sy) of the ECDH point S = r·A_pub
    signal input nonce;          // extContextHash (disclosure context)
    signal output ciphertext[4]; // [c0, c1, c2, tag]

    // KDF — bind both shared-secret coordinates and the nonce.
    component kdf = Poseidon2(3);
    kdf.inputs[0] <== sharedKey[0];
    kdf.inputs[1] <== sharedKey[1];
    kdf.inputs[2] <== nonce;
    kdf.domainSeparation <== 5;

    // Keystream: distinct lane per plaintext element.
    component ks0 = Poseidon2(2);
    ks0.inputs[0] <== kdf.out; ks0.inputs[1] <== 0; ks0.domainSeparation <== 6;
    ciphertext[0] <== plaintext[0] + ks0.out;

    component ks1 = Poseidon2(2);
    ks1.inputs[0] <== kdf.out; ks1.inputs[1] <== 1; ks1.domainSeparation <== 6;
    ciphertext[1] <== plaintext[1] + ks1.out;

    component ks2 = Poseidon2(2);
    ks2.inputs[0] <== kdf.out; ks2.inputs[1] <== 2; ks2.domainSeparation <== 6;
    ciphertext[2] <== plaintext[2] + ks2.out;

    // Authentication tag — chained over the key, ciphertext and nonce.
    component t0 = Poseidon2(3);
    t0.inputs[0] <== kdf.out;
    t0.inputs[1] <== ciphertext[0];
    t0.inputs[2] <== ciphertext[1];
    t0.domainSeparation <== 7;

    component t1 = Poseidon2(3);
    t1.inputs[0] <== t0.out;
    t1.inputs[1] <== ciphertext[2];
    t1.inputs[2] <== nonce;
    t1.domainSeparation <== 7;

    ciphertext[3] <== t1.out;
}

// -----------------------------------------------------------------------------
// Disclose ONE owned note, verifiably encrypted to the auditor.
// -----------------------------------------------------------------------------
template SelectiveDisclosureAudit(levels) {
    // ----- private inputs (the note the discloser owns) -----
    signal input amount;
    signal input privateKey;
    signal input blinding;
    signal input pathIndices;
    signal input pathElements[levels];
    signal input ephemeralScalar;       // auditor-channel randomness r (private)

    // ----- public inputs -----
    signal input merkleRoot;
    signal input auditorPubKey[2];       // Baby JubJub A_pub — MUST be contract-pinned
    signal input extContextHash;         // purpose / authority / pool addr (nonce)

    // ----- public outputs -----
    signal output commitment;
    signal output ephemeralPubKey[2];    // R = r·G
    signal output ciphertext[4];         // C_aud over [amount, blinding, publicKey]

    // 1) derive publicKey and recompute the note commitment (domain sep 0x01)
    component kp = Keypair();
    kp.privateKey <== privateKey;

    component commit = Poseidon2(3);
    commit.inputs[0] <== amount;
    commit.inputs[1] <== kp.publicKey;
    commit.inputs[2] <== blinding;
    commit.domainSeparation <== 0x01;
    commitment <== commit.out;

    // 2) prove the commitment is a member of the pool Merkle tree
    component mp = MerkleProof(levels);
    mp.leaf <== commitment;
    mp.pathIndices <== pathIndices;
    for (var i = 0; i < levels; i++) { mp.pathElements[i] <== pathElements[i]; }
    mp.root === merkleRoot;

    // 3) in-circuit ECDH on Baby JubJub: R = r·G, S = r·A_pub
    component R = BabyPbk();
    R.in <== ephemeralScalar;
    ephemeralPubKey[0] <== R.Ax;
    ephemeralPubKey[1] <== R.Ay;

    component eBits = Num2Bits(253);
    eBits.in <== ephemeralScalar;
    component S = EscalarMulAny(253);
    for (var i = 0; i < 253; i++) { S.e[i] <== eBits.out[i]; }
    S.p[0] <== auditorPubKey[0];
    S.p[1] <== auditorPubKey[1];

    // 4) verifiable encryption of [amount, blinding, publicKey] to the auditor
    component enc = PoseidonAuditEncrypt();
    enc.plaintext[0] <== amount;
    enc.plaintext[1] <== blinding;
    enc.plaintext[2] <== kp.publicKey;
    enc.sharedKey[0] <== S.out[0];
    enc.sharedKey[1] <== S.out[1];
    enc.nonce <== extContextHash;
    for (var i = 0; i < 4; i++) { ciphertext[i] <== enc.ciphertext[i]; }
}

component main { public [merkleRoot, auditorPubKey, extContextHash] } =
    SelectiveDisclosureAudit(10);
