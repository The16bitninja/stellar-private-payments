//! Serializable disclosure records and the auditor batch driver.

use crate::disclosure::AuditDisclosure;
use crate::reconstruct::{RecoveredNote, reconstruct};
use anyhow::{Context, Result};
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Parse a decimal field element.
fn parse_dec(s: &str) -> Result<BigInt> {
    BigInt::from_str(s).with_context(|| format!("invalid decimal field element: {s}"))
}

/// A disclosure record `(commitment, R, C_aud, …)` in decimal-string JSON form —
/// the auditor's data feed entry, as emitted by the pool's `AuditDisclosureEvent`
/// (plus the echoed public inputs needed to verify off-chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureRecord {
    /// Disclosed note commitment.
    pub commitment: String,
    /// Ephemeral Baby JubJub public key `R = r·G` as `[x, y]`.
    pub ephemeral_pub_key: [String; 2],
    /// Verifiable ciphertext `C_aud = [c0, c1, c2, tag]`.
    pub ciphertext: [String; 4],
    /// Pool Merkle root.
    pub merkle_root: String,
    /// Auditor Baby JubJub view key `A_pub` as `[x, y]`.
    pub auditor_pub_key: [String; 2],
    /// Disclosure context hash (encryption nonce).
    pub ext_context_hash: String,
}

impl DisclosureRecord {
    /// Build a record from a parsed disclosure.
    pub fn from_disclosure(d: &AuditDisclosure) -> Self {
        Self {
            commitment: d.commitment.to_string(),
            ephemeral_pub_key: [
                d.ephemeral_pub_key.0.to_string(),
                d.ephemeral_pub_key.1.to_string(),
            ],
            ciphertext: [
                d.ciphertext[0].to_string(),
                d.ciphertext[1].to_string(),
                d.ciphertext[2].to_string(),
                d.ciphertext[3].to_string(),
            ],
            merkle_root: d.merkle_root.to_string(),
            auditor_pub_key: [
                d.auditor_pub_key.0.to_string(),
                d.auditor_pub_key.1.to_string(),
            ],
            ext_context_hash: d.ext_context_hash.to_string(),
        }
    }

    /// Parse this record into a typed [`AuditDisclosure`].
    pub fn to_disclosure(&self) -> Result<AuditDisclosure> {
        Ok(AuditDisclosure {
            commitment: parse_dec(&self.commitment)?,
            ephemeral_pub_key: (
                parse_dec(&self.ephemeral_pub_key[0])?,
                parse_dec(&self.ephemeral_pub_key[1])?,
            ),
            ciphertext: [
                parse_dec(&self.ciphertext[0])?,
                parse_dec(&self.ciphertext[1])?,
                parse_dec(&self.ciphertext[2])?,
                parse_dec(&self.ciphertext[3])?,
            ],
            merkle_root: parse_dec(&self.merkle_root)?,
            auditor_pub_key: (
                parse_dec(&self.auditor_pub_key[0])?,
                parse_dec(&self.auditor_pub_key[1])?,
            ),
            ext_context_hash: parse_dec(&self.ext_context_hash)?,
        })
    }
}

/// The auditor tool's input: the auditor secret key and a batch of disclosures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditorInput {
    /// Auditor Baby JubJub secret key `a` (decimal).
    pub auditor_secret: String,
    /// Disclosure records to reconstruct.
    pub disclosures: Vec<DisclosureRecord>,
}

/// The result of reconstructing one disclosure record.
#[derive(Debug, Clone)]
pub struct ReconstructionOutcome {
    /// The record's claimed commitment (decimal).
    pub commitment: String,
    /// The recovered note, if reconstruction succeeded.
    pub recovered: Option<RecoveredNote>,
    /// A human-readable error, if reconstruction failed.
    pub error: Option<String>,
}

/// Reconstruct every disclosure in `input` using the auditor secret.
///
/// Returns one [`ReconstructionOutcome`] per record (errors are captured
/// per-record, not fatal). Fails only if the auditor secret itself is invalid.
pub fn audit_all(input: &AuditorInput) -> Result<Vec<ReconstructionOutcome>> {
    let secret = parse_dec(&input.auditor_secret).context("invalid auditor secret")?;

    let outcomes = input
        .disclosures
        .iter()
        .map(|record| {
            let commitment = record.commitment.clone();
            match record.to_disclosure().and_then(|d| reconstruct(&secret, &d)) {
                Ok(note) => ReconstructionOutcome {
                    commitment,
                    recovered: Some(note),
                    error: None,
                },
                Err(e) => ReconstructionOutcome {
                    commitment,
                    recovered: None,
                    error: Some(format!("{e:#}")),
                },
            }
        })
        .collect();

    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{babyjub, disclosure::AuditDisclosure, enc};
    use num_bigint::BigInt;
    use zkhash::fields::bn256::FpBN256 as Scalar;

    /// Build a real disclosure for note `amount`, plus the auditor secret.
    fn sample(amount: u64) -> (BigInt, AuditDisclosure) {
        let a = BigInt::from(1234567890123456789u64);
        let r = BigInt::from(9876543210987654321u64);
        let a_pub = babyjub::pubkey(&a);
        let r_point = babyjub::pubkey(&r);
        let s = enc::shared_secret_scalars(babyjub::scalar_mul(&r, a_pub));

        let amount_s = Scalar::from(amount);
        let blinding = Scalar::from(5151u64);
        let public_key = enc::derive_public_key(Scalar::from(4242u64));
        let nonce = Scalar::from(0xC0FFEEu64);
        let ct = enc::encrypt([amount_s, blinding, public_key], s, nonce);

        let d = AuditDisclosure {
            commitment: enc::scalar_to_bigint(enc::commitment(amount_s, public_key, blinding)),
            ephemeral_pub_key: (
                babyjub::fr_to_bigint(r_point.0),
                babyjub::fr_to_bigint(r_point.1),
            ),
            ciphertext: ct.map(enc::scalar_to_bigint),
            merkle_root: BigInt::from(0u64),
            auditor_pub_key: (
                babyjub::fr_to_bigint(a_pub.0),
                babyjub::fr_to_bigint(a_pub.1),
            ),
            ext_context_hash: BigInt::from(0xC0FFEEu64),
        };
        (a, d)
    }

    #[test]
    fn record_roundtrips_disclosure() {
        let (_a, d) = sample(17);
        let record = DisclosureRecord::from_disclosure(&d);
        assert_eq!(record.to_disclosure().expect("valid record"), d);
    }

    #[test]
    fn record_serializes_as_decimal_json() {
        let (_a, d) = sample(17);
        let record = DisclosureRecord::from_disclosure(&d);
        let json = serde_json::to_string(&record).expect("serialize");
        let back: DisclosureRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.to_disclosure().expect("valid"), d);
        // commitment is emitted as a decimal string, not a number.
        assert_eq!(back.commitment, d.commitment.to_string());
    }

    #[test]
    fn audit_all_recovers_each_note() {
        let (a, d1) = sample(17);
        let (_a, d2) = sample(99);
        let input = AuditorInput {
            auditor_secret: a.to_string(),
            disclosures: vec![
                DisclosureRecord::from_disclosure(&d1),
                DisclosureRecord::from_disclosure(&d2),
            ],
        };

        let outcomes = audit_all(&input).expect("auditor run");
        assert_eq!(outcomes.len(), 2);
        assert_eq!(
            outcomes[0].recovered.as_ref().expect("recovered").amount,
            BigInt::from(17u64)
        );
        assert_eq!(
            outcomes[1].recovered.as_ref().expect("recovered").amount,
            BigInt::from(99u64)
        );
    }

    #[test]
    fn audit_all_reports_wrong_key_per_record() {
        let (_a, d) = sample(17);
        let input = AuditorInput {
            auditor_secret: BigInt::from(424242u64).to_string(),
            disclosures: vec![DisclosureRecord::from_disclosure(&d)],
        };

        let outcomes = audit_all(&input).expect("auditor run");
        assert!(outcomes[0].recovered.is_none());
        assert!(outcomes[0].error.is_some());
    }

    #[test]
    fn audit_all_rejects_bad_secret() {
        let input = AuditorInput {
            auditor_secret: "not-a-number".to_string(),
            disclosures: vec![],
        };
        assert!(audit_all(&input).is_err());
    }
}
