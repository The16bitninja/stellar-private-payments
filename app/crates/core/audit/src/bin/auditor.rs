//! Lumenveil auditor tool.
//!
//! Given the auditor's Baby JubJub secret key and a feed of disclosure records
//! `(commitment, R, C_aud, …)` — as emitted by the pool's `AuditDisclosureEvent`
//! — it performs ECDH (`S = a·R`), authenticated decryption of `C_aud`, and a
//! commitment recheck, reconstructing the real note values the public ledger
//! hides. A valid `selectiveDisclosureAudit` proof already guarantees these
//! succeed; this tool is the auditor's convenience layer.
//!
//! Usage:
//!   lumenveil-auditor <disclosures.json>      reconstruct and print the ledger
//!   lumenveil-auditor gen-demo <out.json>     write a runnable sample feed

use anyhow::{Context, Result};
use audit::record::{AuditorInput, DisclosureRecord, audit_all};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let json = args.iter().any(|a| a == "--json");
    let positional: Vec<&str> = args
        .iter()
        .skip(1)
        .filter(|a| !a.starts_with("--"))
        .map(String::as_str)
        .collect();

    let result = match positional.first().copied() {
        Some("gen-demo") => gen_demo(positional.get(1).copied()),
        None if !json => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        Some("-h") => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        Some(path) if json => run_json(path),
        Some(path) => run(path),
        None => {
            print_usage();
            return ExitCode::SUCCESS;
        }
    };

    match result {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1), // some records failed to reconstruct
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!("Lumenveil auditor tool");
    eprintln!("  lumenveil-auditor <disclosures.json>   reconstruct and print the ledger");
    eprintln!("  lumenveil-auditor gen-demo <out.json>  write a runnable sample feed");
}

/// Reconstruct every disclosure in `path` and print the recovered ledger.
/// Returns the number of records that failed to reconstruct.
fn run(path: &str) -> Result<usize> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let input: AuditorInput =
        serde_json::from_str(&raw).with_context(|| format!("parsing {path}"))?;

    let total = input.disclosures.len();
    println!("Lumenveil auditor — reconstructing {total} disclosure(s)\n");

    let outcomes = audit_all(&input)?;
    let mut failures = 0usize;
    for (i, outcome) in outcomes.iter().enumerate() {
        match &outcome.recovered {
            Some(note) => {
                println!("  [{i}] commitment {}", abbreviate(&outcome.commitment));
                println!(
                    "        amount = {}   publicKey = {}   ✓ commitment verified",
                    note.amount,
                    abbreviate(&note.public_key.to_string())
                );
            }
            None => {
                failures = failures.saturating_add(1);
                let reason = outcome.error.as_deref().unwrap_or("unknown error");
                println!(
                    "  [{i}] commitment {} — FAILED: {reason}",
                    abbreviate(&outcome.commitment)
                );
            }
        }
    }

    let recovered = total.saturating_sub(failures);
    println!("\nReconstructed ledger: {recovered}/{total} note(s) recovered.");
    Ok(failures)
}

/// Reconstruct and emit the ledger as a JSON array (for tooling / the UI).
/// Returns the number of records that failed to reconstruct.
fn run_json(path: &str) -> Result<usize> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let input: AuditorInput =
        serde_json::from_str(&raw).with_context(|| format!("parsing {path}"))?;

    let outcomes = audit_all(&input)?;
    let mut failures = 0usize;
    let mut entries: Vec<serde_json::Value> = Vec::with_capacity(outcomes.len());
    for outcome in &outcomes {
        match &outcome.recovered {
            Some(note) => entries.push(serde_json::json!({
                "commitment": outcome.commitment,
                "ok": true,
                "amount": note.amount.to_string(),
                "blinding": note.blinding.to_string(),
                "public_key": note.public_key.to_string(),
            })),
            None => {
                failures = failures.saturating_add(1);
                entries.push(serde_json::json!({
                    "commitment": outcome.commitment,
                    "ok": false,
                    "error": outcome.error,
                }));
            }
        }
    }

    println!("{}", serde_json::to_string(&entries)?);
    Ok(failures)
}

/// Write a small, self-consistent demo feed that the tool can then reconstruct.
fn gen_demo(out: Option<&str>) -> Result<usize> {
    let path = out.context("usage: lumenveil-auditor gen-demo <out.json>")?;
    let input = demo::sample_input();
    let json = serde_json::to_string_pretty(&input).context("serializing demo feed")?;
    std::fs::write(path, json).with_context(|| format!("writing {path}"))?;
    println!(
        "Wrote demo feed with {} disclosure(s) to {path}",
        input.disclosures.len()
    );
    println!("Run: lumenveil-auditor {path}");
    Ok(0)
}

/// Abbreviate a long decimal field element for human-readable output.
fn abbreviate(s: &str) -> String {
    if s.len() <= 18 {
        return s.to_string();
    }
    let head = &s[..10];
    let tail = &s[s.len().saturating_sub(6)..];
    format!("{head}…{tail}")
}

/// Demo-feed construction (an honest sender building disclosures).
mod demo {
    use super::{AuditorInput, DisclosureRecord};
    use audit::{babyjub, disclosure::AuditDisclosure, enc};
    use num_bigint::BigInt;
    use zkhash::fields::bn256::FpBN256 as Scalar;

    /// Auditor secret used by the demo feed.
    fn auditor_secret() -> BigInt {
        BigInt::from(1234567890123456789u64)
    }

    fn disclosure(amount: u64, blinding: u64, private_key: u64, ephemeral: u64) -> AuditDisclosure {
        let a_pub = babyjub::pubkey(&auditor_secret());
        let r = BigInt::from(ephemeral);
        let r_point = babyjub::pubkey(&r);
        let s = enc::shared_secret_scalars(babyjub::scalar_mul(&r, a_pub));

        let amount_s = Scalar::from(amount);
        let blinding_s = Scalar::from(blinding);
        let public_key = enc::derive_public_key(Scalar::from(private_key));
        let nonce = Scalar::from(0xC0FFEE_u64);
        let ciphertext = enc::encrypt([amount_s, blinding_s, public_key], s, nonce);

        AuditDisclosure {
            commitment: enc::scalar_to_bigint(enc::commitment(amount_s, public_key, blinding_s)),
            ephemeral_pub_key: (
                babyjub::fr_to_bigint(r_point.0),
                babyjub::fr_to_bigint(r_point.1),
            ),
            ciphertext: ciphertext.map(enc::scalar_to_bigint),
            merkle_root: BigInt::from(0u64),
            auditor_pub_key: (babyjub::fr_to_bigint(a_pub.0), babyjub::fr_to_bigint(a_pub.1)),
            ext_context_hash: BigInt::from(0xC0FFEE_u64),
        }
    }

    pub fn sample_input() -> AuditorInput {
        let notes = [
            (17u64, 5151u64, 4242u64, 9876543210u64),
            (1_000_000u64, 7777u64, 1111u64, 5555555555u64),
            (42u64, 9090u64, 3333u64, 1234512345u64),
        ];
        let disclosures = notes
            .iter()
            .map(|&(amount, blinding, pk, eph)| {
                DisclosureRecord::from_disclosure(&disclosure(amount, blinding, pk, eph))
            })
            .collect();

        AuditorInput {
            auditor_secret: auditor_secret().to_string(),
            disclosures,
        }
    }
}
