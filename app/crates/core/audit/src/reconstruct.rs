//! Auditor-side reconstruction: recover the hidden note from a disclosure.

use crate::{babyjub, disclosure::AuditDisclosure, enc};
use anyhow::{Result, anyhow};
use num_bigint::BigInt;

/// A note recovered by the auditor from a verifiable disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredNote {
    /// The note amount.
    pub amount: BigInt,
    /// The note blinding factor.
    pub blinding: BigInt,
    /// The note owner's public key.
    pub public_key: BigInt,
    /// The note commitment (recomputed and verified against the disclosure).
    pub commitment: BigInt,
}

/// Recover the hidden note from a disclosure using the auditor's secret key.
///
/// Performs Baby JubJub ECDH (`S = a·R`), authenticated decryption of `C_aud`,
/// and re-derivation of the commitment as an integrity check. Returns an error
/// if the tag fails to authenticate (wrong key or tampered ciphertext) or if the
/// recovered note does not recompute the disclosure's commitment.
///
/// A valid `selectiveDisclosureAudit` Groth16 proof already guarantees both
/// checks pass; this is the auditor's convenience layer, not a trust assumption.
pub fn reconstruct(auditor_secret: &BigInt, d: &AuditDisclosure) -> Result<RecoveredNote> {
    // S = a·R on Baby JubJub.
    let r_point = (
        babyjub::bigint_to_fr(&d.ephemeral_pub_key.0),
        babyjub::bigint_to_fr(&d.ephemeral_pub_key.1),
    );
    let s = babyjub::scalar_mul(auditor_secret, r_point);
    let s_scalars = enc::shared_secret_scalars(s);

    // Authenticated decryption of C_aud under nonce = extContextHash.
    let ciphertext = [
        enc::bigint_to_scalar(&d.ciphertext[0]),
        enc::bigint_to_scalar(&d.ciphertext[1]),
        enc::bigint_to_scalar(&d.ciphertext[2]),
        enc::bigint_to_scalar(&d.ciphertext[3]),
    ];
    let nonce = enc::bigint_to_scalar(&d.ext_context_hash);
    let plaintext = enc::decrypt(ciphertext, s_scalars, nonce)
        .ok_or_else(|| anyhow!("disclosure did not authenticate (wrong key or tampered)"))?;

    // plaintext = [amount, blinding, publicKey]
    let amount = plaintext[0];
    let blinding = plaintext[1];
    let public_key = plaintext[2];

    // Integrity: recovered note must recompute the disclosed commitment.
    let recomputed = enc::commitment(amount, public_key, blinding);
    if enc::scalar_to_bigint(recomputed) != d.commitment {
        return Err(anyhow!("recovered note does not match the disclosed commitment"));
    }

    Ok(RecoveredNote {
        amount: enc::scalar_to_bigint(amount),
        blinding: enc::scalar_to_bigint(blinding),
        public_key: enc::scalar_to_bigint(public_key),
        commitment: d.commitment.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{babyjub, disclosure::AuditDisclosure, enc};
    use num_bigint::BigInt;
    use zkhash::fields::bn256::FpBN256 as Scalar;

    /// Build a disclosure exactly as an honest sender would, for note `amount`.
    fn sample_disclosure(amount: u64) -> (BigInt, AuditDisclosure, BigInt) {
        let a = BigInt::from(1234567890123456789u64); // auditor secret
        let r = BigInt::from(9876543210987654321u64); // ephemeral scalar
        let a_pub = babyjub::pubkey(&a);
        let r_point = babyjub::pubkey(&r);
        let s = babyjub::scalar_mul(&r, a_pub); // sender S = r·A_pub
        let s_scalars = enc::shared_secret_scalars(s);

        let amount_s = Scalar::from(amount);
        let blinding = Scalar::from(5151u64);
        let priv_key = Scalar::from(4242u64);
        let public_key = enc::derive_public_key(priv_key);
        let nonce = Scalar::from(0xC0FFEEu64);

        let ct = enc::encrypt([amount_s, blinding, public_key], s_scalars, nonce);
        let commitment = enc::commitment(amount_s, public_key, blinding);

        let disclosure = AuditDisclosure {
            commitment: enc::scalar_to_bigint(commitment),
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
        (a, disclosure, enc::scalar_to_bigint(public_key))
    }

    #[test]
    fn auditor_recovers_note() {
        let (a, disclosure, expected_pk) = sample_disclosure(17);

        let note = reconstruct(&a, &disclosure).expect("auditor should recover note");

        assert_eq!(note.amount, BigInt::from(17u64));
        assert_eq!(note.blinding, BigInt::from(5151u64));
        assert_eq!(note.public_key, expected_pk);
        assert_eq!(note.commitment, disclosure.commitment);
    }

    #[test]
    fn wrong_auditor_secret_fails() {
        let (_a, disclosure, _pk) = sample_disclosure(17);
        let wrong = BigInt::from(424242u64);

        assert!(reconstruct(&wrong, &disclosure).is_err());
    }

    #[test]
    fn commitment_mismatch_is_rejected() {
        // Ciphertext encrypts amount=17, but the disclosure's commitment is for
        // amount=18: decryption authenticates, yet the recovered note does not
        // recompute the claimed commitment.
        let (a, mut disclosure, _pk) = sample_disclosure(17);
        let (_a2, other, _pk2) = sample_disclosure(18);
        disclosure.commitment = other.commitment;

        assert!(reconstruct(&a, &disclosure).is_err());
    }
}
