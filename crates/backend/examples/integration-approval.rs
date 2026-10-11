//! Integration-only signing oracle. Custody arrives over stdin, never argv.
//! The recovery root must match the canonical registration checkpoint; this
//! oracle cannot invent a DID document or an admin identity.

use std::io::{self, Read as _};

use anyhow::{Context as _, Result, ensure};
use arkret_identifiers::{Did, DidCoreId, project_did_to_core_id};
use ed25519_dalek_3::{Signer as _, SigningKey};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    recovery_key: String,
    principal_did: Did,
    root_public_key_multibase: String,
    root_verification_method: String,
    proposal_id: String,
    account_id: ulid::Ulid,
    action: String,
    ticket: Option<String>,
    approval_note: String,
    approved_by: DidCoreId,
}

fn main() -> Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let input: Input = serde_json::from_str(&input).context("read approval request")?;
    ensure!(
        project_did_to_core_id(&input.principal_did)? == input.approved_by,
        "approval actor differs from its accepted registration principal"
    );
    let root = arkret_crypto::identity_root::derive_identity_recovery_key_material_from_bip39(
        &input.recovery_key,
        "",
        0,
    )?;
    ensure!(
        root.root_public_key_multikey == input.root_public_key_multibase,
        "recovery custody differs from the accepted registration root"
    );
    ensure!(
        input.root_verification_method
            == format!(
                "did:key:{}#{}",
                root.root_public_key_multikey, root.root_public_key_multikey
            ),
        "approval method differs from the accepted native root method"
    );
    let mut transcript = json!({
        "type": "org.arkret.coauth.account_risk_action.approval.v1",
        "proposal_id": input.proposal_id,
        "account_id": input.account_id,
        "action": input.action,
        "approval_note": input.approval_note,
        "approved_by": input.approved_by,
    });
    if let Some(ticket) = input.ticket {
        transcript["ticket"] = Value::String(ticket);
    }
    let bytes = arkret_canonical::canonical_json_bytes(&transcript)?;
    let signing_input = arkret_signatures::ed25519_detached_jws_signing_input(
        &bytes,
        Some(&input.root_verification_method),
    )?;
    let signature = SigningKey::from_bytes(&root.root_seed).sign(signing_input.as_bytes());
    let jws = arkret_signatures::ed25519_detached_jws_from_signature(
        &signature.to_bytes(),
        Some(&input.root_verification_method),
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({ "approval_proof_jws": jws }))?
    );
    Ok(())
}
