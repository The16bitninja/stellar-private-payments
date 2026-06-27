//! Typed representation of a `selectiveDisclosureAudit` proof and its witness.

use anyhow::{Result, anyhow};
use num_bigint::{BigInt, Sign};

/// Number of public signals a `selectiveDisclosureAudit` proof exposes:
/// the three outputs (commitment, R, C_aud → 7 elements) followed by the four
/// public inputs (merkleRoot, auditorPubKey → 2 elements, extContextHash).
pub const AUDIT_PUBLIC_SIGNAL_COUNT: usize = 11;

/// Byte width of one BN254 field element in the prover's public-input encoding.
const FIELD_BYTES: usize = 32;

/// The decoded public signals of a `selectiveDisclosureAudit` proof.
///
/// Public-signal order (outputs then public inputs):
/// `[commitment, R.x, R.y, c0, c1, c2, tag, merkleRoot, A.x, A.y, extContextHash]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditDisclosure {
    /// The disclosed note commitment (a Merkle-tree member).
    pub commitment: BigInt,
    /// Ephemeral Baby JubJub public key `R = r·G`.
    pub ephemeral_pub_key: (BigInt, BigInt),
    /// Verifiable ciphertext `C_aud = [c0, c1, c2, tag]`.
    pub ciphertext: [BigInt; 4],
    /// Pool Merkle root the membership proof was generated against.
    pub merkle_root: BigInt,
    /// Auditor Baby JubJub view key `A_pub` echoed as a public input.
    pub auditor_pub_key: (BigInt, BigInt),
    /// Disclosure context hash used as the encryption nonce.
    pub ext_context_hash: BigInt,
}

/// Decode a field element from a 32-byte little-endian chunk.
fn field_le(chunk: &[u8]) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, chunk)
}

/// Parse the prover's public-input byte vector (as produced by
/// `Prover::extract_public_inputs`) into a typed [`AuditDisclosure`].
///
/// Expects exactly [`AUDIT_PUBLIC_SIGNAL_COUNT`] field elements, each a 32-byte
/// little-endian value, in circuit order.
pub fn parse_public_signals(bytes: &[u8]) -> Result<AuditDisclosure> {
    let expected = AUDIT_PUBLIC_SIGNAL_COUNT
        .checked_mul(FIELD_BYTES)
        .ok_or_else(|| anyhow!("signal size overflow"))?;
    if bytes.len() != expected {
        return Err(anyhow!(
            "expected {expected} bytes ({AUDIT_PUBLIC_SIGNAL_COUNT} field elements), got {}",
            bytes.len()
        ));
    }

    let elem = |i: usize| -> BigInt {
        let start = i * FIELD_BYTES;
        field_le(&bytes[start..start + FIELD_BYTES])
    };

    Ok(AuditDisclosure {
        commitment: elem(0),
        ephemeral_pub_key: (elem(1), elem(2)),
        ciphertext: [elem(3), elem(4), elem(5), elem(6)],
        merkle_root: elem(7),
        auditor_pub_key: (elem(8), elem(9)),
        ext_context_hash: elem(10),
    })
}

/// Typed witness inputs for the `selectiveDisclosureAudit` circuit.
///
/// All values are canonical field elements; `path_elements` has length equal to
/// the circuit's Merkle depth (10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditWitnessInputs {
    /// Note amount (private).
    pub amount: BigInt,
    /// Note owner's private key (private).
    pub private_key: BigInt,
    /// Note blinding factor (private).
    pub blinding: BigInt,
    /// Packed Merkle path indices (private).
    pub path_indices: BigInt,
    /// Merkle path sibling elements (private).
    pub path_elements: Vec<BigInt>,
    /// Pool Merkle root (public).
    pub merkle_root: BigInt,
    /// Ephemeral ECDH scalar `r` (private).
    pub ephemeral_scalar: BigInt,
    /// Auditor Baby JubJub view key `A_pub` (public, contract-pinned).
    pub auditor_pub_key: (BigInt, BigInt),
    /// Disclosure context hash / encryption nonce (public).
    pub ext_context_hash: BigInt,
}

impl AuditWitnessInputs {
    /// Serialize to the circom witness-input JSON expected by the witness
    /// calculator (decimal-string scalars; arrays for vector signals).
    pub fn to_inputs_json(&self) -> String {
        let dec = |n: &BigInt| n.to_string();
        let arr = |v: &[BigInt]| v.iter().map(dec).collect::<Vec<_>>();

        let value = serde_json::json!({
            "amount": dec(&self.amount),
            "privateKey": dec(&self.private_key),
            "blinding": dec(&self.blinding),
            "pathIndices": dec(&self.path_indices),
            "pathElements": arr(&self.path_elements),
            "merkleRoot": dec(&self.merkle_root),
            "ephemeralScalar": dec(&self.ephemeral_scalar),
            "auditorPubKey": [dec(&self.auditor_pub_key.0), dec(&self.auditor_pub_key.1)],
            "extContextHash": dec(&self.ext_context_hash),
        });
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    /// 32-byte little-endian encoding of a small integer (a public signal).
    fn le32(n: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_le_bytes());
        b
    }

    fn signals(vals: &[u64]) -> Vec<u8> {
        vals.iter().flat_map(|&n| le32(n)).collect()
    }

    #[test]
    fn parses_public_signals_in_circuit_order() {
        // [commitment, R.x, R.y, c0, c1, c2, tag, merkleRoot, A.x, A.y, nonce]
        let buf = signals(&[100, 11, 22, 1001, 1002, 1003, 1004, 200, 33, 44, 0xC0FFEE]);
        let d = parse_public_signals(&buf).expect("parse should succeed");

        assert_eq!(d.commitment, BigInt::from(100u64));
        assert_eq!(
            d.ephemeral_pub_key,
            (BigInt::from(11u64), BigInt::from(22u64))
        );
        assert_eq!(
            d.ciphertext,
            [1001u64, 1002, 1003, 1004].map(BigInt::from)
        );
        assert_eq!(d.merkle_root, BigInt::from(200u64));
        assert_eq!(d.auditor_pub_key, (BigInt::from(33u64), BigInt::from(44u64)));
        assert_eq!(d.ext_context_hash, BigInt::from(0xC0FFEEu64));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(parse_public_signals(&[0u8; 100]).is_err());
        assert!(parse_public_signals(&[]).is_err());
    }

    #[test]
    fn witness_inputs_serialize_to_circom_json() {
        let inputs = AuditWitnessInputs {
            amount: BigInt::from(17u64),
            private_key: BigInt::from(4242u64),
            blinding: BigInt::from(5151u64),
            path_indices: BigInt::from(9u64),
            path_elements: vec![BigInt::from(1u64), BigInt::from(2u64)],
            merkle_root: BigInt::from(999u64),
            ephemeral_scalar: BigInt::from(7u64),
            auditor_pub_key: (BigInt::from(33u64), BigInt::from(44u64)),
            ext_context_hash: BigInt::from(0xC0FFEEu64),
        };

        let json = inputs.to_inputs_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        assert_eq!(v["amount"].as_str(), Some("17"));
        assert_eq!(v["privateKey"].as_str(), Some("4242"));
        assert_eq!(v["blinding"].as_str(), Some("5151"));
        assert_eq!(v["pathIndices"].as_str(), Some("9"));
        assert_eq!(v["merkleRoot"].as_str(), Some("999"));
        assert_eq!(v["ephemeralScalar"].as_str(), Some("7"));
        assert_eq!(v["extContextHash"].as_str(), Some("12648430"));
        assert_eq!(v["pathElements"], serde_json::json!(["1", "2"]));
        assert_eq!(v["auditorPubKey"], serde_json::json!(["33", "44"]));
    }
}
