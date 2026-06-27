//! Lumenveil auditor view-key support.
//!
//! Pure (no witness/prover dependencies) building blocks for the verifiable
//! selective-disclosure scheme: the Baby JubJub curve used for in-circuit ECDH,
//! the Poseidon2 authenticated-encryption mirror, the typed representation of a
//! `selectiveDisclosureAudit` proof's public signals, and the auditor-side
//! reconstruction that recovers the hidden note from `(R, C_aud)`.

pub mod babyjub;
pub mod disclosure;
pub mod enc;
pub mod record;
pub mod reconstruct;

#[cfg(feature = "prover")]
pub mod wiring;
