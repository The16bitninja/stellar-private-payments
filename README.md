<div align="center">

<!-- Drop a 120×120 logo at ./app/lumenveil-ui/public/lumenveil-icon.png and uncomment:
<img src="./app/lumenveil-ui/public/lumenveil-icon.png" alt="Lumenveil logo" width="120" height="120" />
-->

# Lumenveil

### Compliant privacy on Stellar — verifiable disclosure to a designated auditor

*See nothing. Audit everything.*

[![Stellar](https://img.shields.io/badge/Stellar-testnet-7d00ff)](https://stellar.expert/explorer/testnet/contract/CBX7YVYTTTOAMAP4BD727SFNVES2Y6UBKMQC243SKTAOJT5LE7ED52V4)
[![Soroban](https://img.shields.io/badge/Soroban-Rust-08b5e5?logo=rust&logoColor=white)](https://soroban.stellar.org/)
[![Circom](https://img.shields.io/badge/Circom-Groth16-2a2a72)](https://docs.circom.io/)
[![BN254](https://img.shields.io/badge/curve-BN254%20%2F%20BabyJubJub-22d3ee)](https://docs.circom.io/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

*Built for **Stellar Hacks: Real-World ZK** (Stellar Development Foundation), on Nethermind's [`stellar-private-payments`](https://github.com/NethermindEth/stellar-private-payments).*

</div>

---

## Table of Contents

- [Project Overview](#project-overview)
- [Problem Statement](#problem-statement)
- [Our Approach](#our-approach)
- [Challenges We Faced](#challenges-we-faced)
- [Technologies We Used](#technologies-we-used)
- [Architecture & Diagrams](#architecture--diagrams)
- [Scope & Honest Caveats](#scope--honest-caveats)
- [Installation & Setup Guide](#installation--setup-guide)
- [Team](#team)
- [Contract Deployment](#contract-deployment)

---

## Project Overview

**Lumenveil** adds **compliant privacy** to a Stellar privacy pool. A shielded pool
already hides amounts and counterparties from everyone — which is a non-starter for
regulated finance. Lumenveil keeps each transaction private from the **public** while
making one **designated auditor cryptographically guaranteed** to recover the true value.

Per disclosed note it produces a ciphertext only the auditor can open, **together with a
zero-knowledge proof that the ciphertext correctly encrypts the very value committed
on-chain.** The public sees an opaque field element; the auditor (and only the auditor)
sees the truth; and because a dishonest ciphertext cannot produce a valid proof, **nobody
can lie to the auditor.** It lands squarely on SDF's zkKYC / selective-disclosure theme.

> A privacy pool hides every transaction from everyone. Lumenveil removes that
> all-or-nothing trade-off: unconditional privacy from the public, and mandatory,
> cryptographically-guaranteed transparency to exactly one auditor.

This is a focused contribution **on top of** Nethermind's Apache-2.0
`stellar-private-payments` PoC (its original README is preserved as
[`README.upstream.md`](./README.upstream.md)). The new, load-bearing work is the
`selectiveDisclosureAudit` circuit and everything wired around it — see
[Contract Deployment](#contract-deployment) for the live testnet proof.

---

## Problem Statement

A regulated institution wants to use a shielded pool but must still answer to an auditor.
The upstream pool encrypts each output note to its **recipient off-circuit (X25519)** and
binds those ciphertext bytes to the proof via `extDataHash`. That binding proves *which
bytes were committed to* — it **never proves those bytes are a correct encryption of the
committed note.** That gap breaks mandatory auditing in three ways:

1. **Byte-binding is not correctness.** `extDataHash` pins the ciphertext's bytes, not its
   meaning. A sender can bind random bytes and the transaction still verifies.
2. **A recipient is self-policing; a mandatory auditor is not.** If a sender encrypts
   garbage to a *recipient*, the recipient just can't spend their note — the sender only
   hurts themselves. Encrypt garbage to the *auditor* and the regulator goes blind, with
   no on-chain signal that anything is wrong.
3. **The auditor would have to trust the sender.** Without a proof of correctness, an
   auditor inspecting the "auditor copy" is trusting the very party it is auditing.

Lumenveil makes the auditor's copy **cryptographically tamper-evident**: change the
plaintext and the in-circuit commitment check breaks; encrypt to a key you control and the
proof fails against the contract-pinned auditor key.

---

## Our Approach

The note's **commitment** stays on-chain. The auditor's **ciphertext** rides alongside it.
A single ZK proof is the bridge that guarantees the two agree.

The auditor holds a **Baby JubJub** keypair `A_pub = a·G` — a twisted-Edwards curve whose
base field *is* BN254's scalar field, so elliptic-curve math is cheap **inside** a Groth16
circuit (X25519 would cost millions of constraints). Encryption uses a **Poseidon2**
keystream-and-tag cipher, so the cipher is SNARK-friendly *and* reproduces bit-for-bit in
off-circuit Rust — which is what lets the auditor actually decrypt.

### 1. Prove ownership and recompute the commitment
The circuit derives `publicKey = Keypair(privateKey)` and recomputes
`commitment = Poseidon2(amount, publicKey, blinding)`, then proves that commitment is a
member of the pool's Merkle tree (depth 10). This binds the proof to a real, owned note.

### 2. Verifiably encrypt to the auditor — in-circuit
Sender samples an ephemeral scalar `r`, computes `R = r·G` (published) and the shared
secret `S = r·A_pub`. The auditor later recomputes the same `S = a·R`. A Poseidon2 cipher
turns `[amount, blinding, publicKey]` into `C_aud = [c0, c1, c2, tag]` under `S` and the
disclosure-context nonce `extContextHash`. All of this is **constrained by the proof**.

### 3. Anchor the disclosure on-chain
The pool's `disclose` emits an `AuditDisclosureEvent` carrying
`(commitment, R, C_aud, extContextHash)` — everything the auditor needs, and nothing the
public can read.

### 4. Reconstruct trustlessly
The auditor scans the event, derives `S = a·R`, authenticated-decrypts `C_aud`, then
**re-derives the commitment** from the recovered values and checks it matches the chain.

```bash
# Scan the deployed pool for disclosures and reconstruct with the auditor secret:
node auditor/scan.mjs --run     # finds AuditDisclosureEvents → pipes to lumenveil-auditor
# → recovered: amount = 17, ✓ commitment verified  (from on-chain data + the secret alone)
```

The eleven public signals are fixed and load-bearing (the parser depends on the order),
each a 32-byte little-endian BN254 field element:

```
[ commitment, R.x, R.y, c0, c1, c2, tag, merkleRoot, A.x, A.y, extContextHash ]
```

---

## Challenges We Faced

### Circom / ZK
- **Bit-exactness between Circom and Rust.** The hardest risk in the project: the
  in-circuit Baby JubJub + Poseidon2 and the off-circuit Rust must agree to the last field
  element, or decryption silently fails. We built a dependency-free Rust mirror of both and
  test it against the **real compiled circuit** before trusting either side.
- **A Merkle-depth mismatch.** An early draft used depth 20; the deployed `policy_tx_2_2`
  tree is depth 10. Membership proofs only line up at the right depth — caught and fixed.

### Soroban / Contracts
- **The auditor key must be contract-pinned.** `auditorPubKey` is a *public input*; if a
  sender could choose it, they could "verifiably encrypt" to a key only they hold. So the
  pool pins it (`set_auditor_pubkey`, admin-only) with canonical-field validation.
- **The event wasn't reconstruction-sufficient.** Capturing the real event ABI revealed the
  auditor needs the nonce (`extContextHash`) to decrypt, but the first event didn't carry
  it. We threaded `ext_context_hash` through `disclose` and the event, so the event alone
  now suffices for recovery.

### Rust crate / Tooling
- **Keeping the auditor lightweight.** The auditor only decrypts and must not drag in the
  `wasmer`/witness/prover stack — so the prover wiring lives behind a `--features prover`
  flag and the default build stays small.
- **Cross-library field conversions.** `ark_bn254::Fr` and zkhash's `FpBN256` are both
  `PrimeField` over the same modulus, so all conversions go via little-endian bytes to stay
  exactly consistent with the circuit.

### Frontend (Next.js 16 + Vercel)
- **Serverless can't spawn a native binary.** The local UI shells the real Rust auditor;
  on Vercel it can't. The hosted build does a **genuine live RPC scan** and replays the
  auditor's recorded reconstruction (correct key reveals the note, any other key fails) —
  documented in-code so the boundary is honest.
- **Next 16 ergonomics.** Route handlers run on the Node runtime with the Stellar SDK
  marked as a server-external package; the workspace root is pinned (the repo has several
  lockfiles).

---

## Technologies We Used

![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)
![Soroban](https://img.shields.io/badge/Soroban-08b5e5)
![Circom](https://img.shields.io/badge/Circom-2a2a72)
![Groth16](https://img.shields.io/badge/Groth16-arkworks-FE7A16)
![BN254](https://img.shields.io/badge/BN254-BabyJubJub-22d3ee)
![Poseidon2](https://img.shields.io/badge/Poseidon2-zkhash-6fbcf0)
![Next.js](https://img.shields.io/badge/Next.js_16-000000?logo=nextdotjs&logoColor=white)
![React](https://img.shields.io/badge/React_19-20232A?logo=react&logoColor=61DAFB)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_v4-38B2AC?logo=tailwindcss&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-339933?logo=nodedotjs&logoColor=white)

- **Circuit:** `selectiveDisclosureAudit.circom` — proves ownership + verifiable encryption
  to the auditor (Circom 2 → Groth16 over BN254, arkworks). **5/5** tests.
- **Contracts:** Soroban (Rust). `pool` adds `set_auditor_pubkey` / `disclose` /
  `AuditDisclosureEvent` (**25/25**); `public-key-registry` adds `register_auditor` /
  `auditor_key` (**13/13**).
- **Crypto crate:** `app/crates/core/audit` — Baby JubJub, the Poseidon2 cipher, ECDH,
  reconstruction, and the prover wiring (feature-gated). **22** pure tests + **1** prover
  end-to-end.
- **Auditor tools:** Node/ESM `scan.mjs` (live event scanner) + `disclose.mjs` (on-chain
  submitter). **7/7** tests. Plus a full circuit→pool→auditor integration test.
- **Web UI:** Next.js 16 + React 19 + Tailwind v4 + Framer Motion, with a live `/api`
  backend that scans the deployed pool and reconstructs disclosures.

---

## Architecture & Diagrams

The contract stores the **fingerprint** (`commitment`); the auditor's **content** rides in
the event ciphertext; the ZK proof guarantees the two agree. The deployed verifier and the
consensus transaction path are left **untouched** — the disclosure circuit is verified off
the spend path ("Route 2").

```
SENDER (off-chain proving)
  private:  amount, privateKey, blinding, Merkle path, ephemeral r
  public:   merkleRoot, A_pub (contract-pinned), extContextHash
  circuit:  publicKey, commitment, R = r·G, S = r·A_pub, C_aud = Poseidon2-encrypt(...)
  output:   Groth16 proof + 11 public signals

ON-CHAIN  pool.disclose(...)  ── emits AuditDisclosureEvent ──▶
  topics:   [ Symbol("audit_disclosure_event"), commitment ]
  data:     { ciphertext:[c0,c1,c2,tag], ephemeral_pub_key:{x,y}, ext_context_hash }
  (the public sees only opaque field elements)

AUDITOR (holds secret a)
  scan event → S = a·R → authenticated-decrypt C_aud → (amount, blinding, publicKey)
            → recompute Poseidon2(amount, publicKey, blinding) → assert == commitment ✓
  result:   the true amount, guaranteed honest by the proof
```

- **Write path:** Sender → prover (`lumenveil-disclose`) → `disclose.mjs` → pool emits the event.
- **Read/verify path:** `scan.mjs` reads the event → `lumenveil-auditor` decrypts and
  re-checks the commitment → reveals the note or rejects a wrong key / tampered ciphertext.

---

## Scope & Honest Caveats

A research prototype on **testnet**, unaudited. Stated plainly because rigor matters:

- **Route 2 is a deliberate choice.** The disclosure circuit is standalone and verified off
  the consensus path, keeping the deployed verifier and transaction circuit untouched. The
  trade-off: an audit disclosure is produced per note rather than being mandatory at every
  transfer.
- **On the live loop, the proof is generated and test-verified, not yet verified on-chain.**
  `disclose` is a transport/feed; the auditor decrypts and re-checks the commitment. Full
  Groth16 verification runs in the Rust tests and is meant to run off-chain against the
  exported VK (with `auditorPubKey == pinned`). Wiring that into the live path is the next step.
- **Trusted setup** is a single-contributor hackathon setup, not a ceremony.
- **Event retention** on Stellar RPC is ~7 days; a production auditor needs an indexer. The
  UI caches a snapshot as a stopgap.

---

## Installation & Setup Guide

Prereqs: Rust (stable + `wasm32`), Node/npm, `circom`, and the Stellar CLI (`stellar`).

### Circuit
```bash
cargo build -p circuits
cargo test  -p circuits        # real proof generation + verification, 5/5
```

### Contracts
```bash
cd contracts/pool                 && cargo test     # 25/25
cd ../public-key-registry         && cargo test     # 13/13
```

### Crypto crate (auditor + prover)
```bash
cd app/crates/core/audit
cargo test                        # 22 pure tests
cargo test --features prover      # + 1 prover end-to-end
```

### Auditor tools (Node)
```bash
cd auditor
npm install
npm test                          # 7/7 (scanner + submitter, incl. ScVal round-trips)

node scan.mjs --run               # scan the live pool and reconstruct with the auditor key
```

### Web UI
```bash
cd app/lumenveil-ui
npm install
npm run dev                       # http://localhost:3000
```
Paste the auditor key in the **Auditor Console** to decrypt the real on-chain ciphertext —
it reveals **17 XLM, ✓ commitment verified**; a wrong key is rejected.

> **Deploying the UI to Vercel:** set the project's **Root Directory** to `app/lumenveil-ui`
> (the Next.js app is a subfolder of this repo). No environment variables are required.

---

## Team

- [The16bitninja (Vedant Tarale)](https://github.com/The16bitninja)
<!-- add teammates: - [Name](https://github.com/handle) -->

---

## Contract Deployment

Live on **Stellar testnet**. The audit-enabled pool, the pinned auditor key, and the first
on-chain disclosure are all real — the auditor reconstructed **amount = 17** from on-chain
data plus the secret alone.

| Contract | Address |
|---|---|
| **Pool** (audit-enabled) ⭐ | [`CBX7YVYT…52V4`](https://stellar.expert/explorer/testnet/contract/CBX7YVYTTTOAMAP4BD727SFNVES2Y6UBKMQC243SKTAOJT5LE7ED52V4) |
| Public Key Registry | [`CBJT4I7K…AIEC`](https://stellar.expert/explorer/testnet/contract/CBJT4I7KB4WHIPHFHYFUBZSQNBUY4GYD5TXJNUANAK5WI73BGACGAIEC) |
| Groth16 Verifier | [`CB2OYSTW…CFPT`](https://stellar.expert/explorer/testnet/contract/CB2OYSTWNSQWF62LLJKIGPO6VXMETGEPUX747IXBCL6H7RJRHL3QCFPT) |
| ASP Membership | [`CDJCRJDR…QXDD`](https://stellar.expert/explorer/testnet/contract/CDJCRJDRZVTU6BZLR4ZPVNTZ3RBCS2OIDN3FUTVZTUBU7MWPPYIOQXDD) |
| ASP Non-Membership | [`CBOSS6IW…QNBH`](https://stellar.expert/explorer/testnet/contract/CBOSS6IWL5PMTNXHAPW4DSY6BR7ZHXPPEHL3KE3R2NQ24QM463HOQNBH) |
| Token (native XLM) | [`CDLZFC3S…CYSC`](https://stellar.expert/explorer/testnet/contract/CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC) |
| Deployer / Admin | [`GBLK2CTO…4AJG`](https://stellar.expert/explorer/testnet/account/GBLK2CTOGPTSHKHLKGCH3IFFMFLC3QDGGWFU7O6O65L3OMV5LLJ34AJG) |

**The live capstone, in three transactions:**

| Step | Transaction |
|---|---|
| Deploy the audit-enabled pool | [`c971654…`](https://stellar.expert/explorer/testnet/tx/c971654efa19d22acd098a649d56c1809743e4a1b44ffe366cf2c608280fe9b4) |
| Pin the auditor key (`set_auditor_pubkey`) | [`d3593fe…`](https://stellar.expert/explorer/testnet/tx/d3593fe369f52158f2664749c31edcdb26598f8cc19ca7743a5c8c3d7918b3e0) |
| Emit the first disclosure (`disclose`) | [`ce9e074e…`](https://stellar.expert/explorer/testnet/tx/ce9e074e470768d0a3b6daaa295c72b69afc4c4b5ac9ac43e07f9dc9e63ac6cc) |

**Live demo:** https://stellar-private-payments-eta.vercel.app/ *(goes live once the Vercel
Root Directory is set to `app/lumenveil-ui`).*

---

<div align="center">

*Lumenveil is a derivative work of Nethermind's `stellar-private-payments` (Apache-2.0).
The upstream LICENSE is preserved; all Lumenveil-original files carry their own headers.*

**See nothing. Audit everything.**

</div>
