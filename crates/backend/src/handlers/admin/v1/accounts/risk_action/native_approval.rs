//! Local admin approvals consume the Station's verified current native control
//! pin. The proof contributes a key locator and signature, never authority.

use arkret_identifiers::{Did, DidCoreId, Hash, project_did_to_core_id};
use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret_wire::DidUrl;

use crate::services::did_resolver::DidResolution;

pub(super) fn verify_native_approval_jws(
    resolution: &DidResolution,
    principal: &DidCoreId,
    payload: &[u8],
    proof: &str,
) -> Result<String, String> {
    let did = Did::new(resolution.document.id.clone()).map_err(|error| error.to_string())?;
    if did.method() != "webvh"
        || project_did_to_core_id(&did).map_err(|error| error.to_string())? != *principal
        || resolution.identity_fact_rejection().is_some()
        || resolution.key_log_head.is_none()
    {
        return Err("current native authority does not bind the accepted admin principal".into());
    }
    let Some(arkret_models_identity::IdentityMethodEvidence::DidWebvh {
        version_id: _,
        control_key_digest,
    }) = &resolution.closed_method_evidence
    else {
        return Err("current verified method-control pins are missing".into());
    };
    let verifier = Ed25519DetachedJwsVerifier::new();
    let method = verifier
        .detached_jws_key_id(proof)
        .map_err(|error| error.to_string())?
        .ok_or("approval proof has no protected kid")?;
    let (key_did, fragment) = method.split_once('#').ok_or("native key has no fragment")?;
    let multibase = key_did
        .strip_prefix("did:key:")
        .ok_or("native key is not did:key")?;
    if fragment != multibase {
        return Err("native key fragment is not exact canonical Multikey".into());
    }
    let key =
        arkret_canonical::decode_ed25519_multibase(multibase).map_err(|error| error.to_string())?;
    if arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key) != multibase {
        return Err("native key encoding is not canonical".into());
    }
    let digest = Hash::new(format!("sha256:{}", arkret_canonical::sha256_hex(key)))
        .map_err(|error| error.to_string())?;
    if &digest != control_key_digest {
        return Err("approval root is not the current verified method-control key".into());
    }
    // Check the closed principal profile, including root-key separation.
    arkret_signatures::webvh::validate_principal_did_document_profile(
        did.as_str(),
        &serde_json::to_value(&resolution.document).map_err(|error| error.to_string())?,
        &[multibase],
    )
    .map_err(|error| error.to_string())?;
    let native =
        arkret_identity::principal_control::native_identity_control_key_from_verified_selection(
            &did,
            principal,
            &[multibase.to_owned()],
            &DidUrl::new(method.clone()).map_err(str::to_owned)?,
            arkret_identity::principal_control::DirectIdentityControlPurpose::ApprovalSignature,
        )
        .map_err(|error| error.to_string())?;
    let verified = verifier
        .verify_detached_jws_with_metadata(
            proof,
            payload,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: native.public_key().to_vec(),
            },
        )
        .map_err(|error| error.to_string())?;
    if verified.key_id() != Some(method.as_str()) {
        return Err("protected kid changed during verification".into());
    }
    Ok(method)
}

#[cfg(test)]
mod tests {
    use arkret_signatures::webvh::{PrincipalInceptionInput, PrincipalRotationInput};
    use arkret_wire::NonEmptyString;
    use serde_json::json;

    use super::*;
    use crate::services::did_resolver::{DidResolutionIdentityFactRejection, DidResolutionSource};

    fn multikey(seed: &[u8; 32]) -> String {
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(seed)
                .verifying_key()
                .to_bytes(),
        )
    }

    fn proof(seed: &[u8; 32], method: &str, payload: &[u8]) -> String {
        crate::arkret_key_bridge::sdk_detached_jws_for_test(seed, method, payload)
    }

    // Recreate only the existing resolver's closed product response from a
    // complete SDK-verified principal history; no fake document VM is added.
    fn resolution(did: &Did, entries: &[serde_json::Value]) -> DidResolution {
        let verified =
            arkret_identity::verify_did_webvh_v1_log_and_witness_records(did, entries, &[])
                .unwrap();
        let key = arkret_canonical::decode_ed25519_multibase(&verified.log.active_update_keys[0])
            .unwrap();
        DidResolution {
            document: serde_json::from_value(verified.log.head_state).unwrap(),
            source: DidResolutionSource::DelegatedResolver,
            verified_local_binding: false,
            key_log_head: Some(
                Hash::new(arkret_canonical::canonical_sha256(entries.last().unwrap()).unwrap())
                    .unwrap(),
            ),
            method_evidence: json!({}),
            closed_method_evidence: Some(
                arkret_models_identity::IdentityMethodEvidence::DidWebvh {
                    version_id: NonEmptyString::new(verified.log.head_version_id).unwrap(),
                    control_key_digest: Hash::new(format!(
                        "sha256:{}",
                        arkret_canonical::sha256_hex(key)
                    ))
                    .unwrap(),
                },
            ),
            identity_fact_rejection: None,
        }
    }

    #[test]
    fn native_admin_approval_binds_current_rotated_root_without_document_vm() {
        let old = [0x61; 32];
        let current = [0x62; 32];
        let endpoint = "https://native-admin.example/".parse().unwrap();
        let at = "2026-10-01T00:00:00Z".parse().unwrap();
        let inception =
            arkret_signatures::webvh::prepare_principal_inception(&PrincipalInceptionInput {
                provider_endpoint: &endpoint,
                principal_endpoint: &endpoint,
                local_id: "admin",
                also_known_as: &[],
                version_time: at,
                root_seed: &old,
                next_root_public_key_multibase: &multikey(&current),
                witness_policy: None,
            })
            .unwrap();
        let did = Did::new(&inception.did).unwrap();
        let principal = project_did_to_core_id(&did).unwrap();
        let old_method = format!("did:key:{}#{}", multikey(&old), multikey(&old));
        let current_method = format!("did:key:{}#{}", multikey(&current), multikey(&current));
        let payload = b"exact local admin transcript";
        let initial = resolution(&did, std::slice::from_ref(&inception.log_entry));
        assert!(initial.document.verification_method.is_empty());
        assert!(
            verify_native_approval_jws(
                &initial,
                &principal,
                payload,
                &proof(&old, &old_method, payload)
            )
            .is_ok()
        );
        let rotation =
            arkret_signatures::webvh::prepare_principal_rotation(&PrincipalRotationInput {
                did: did.as_str(),
                local_id: "admin",
                previous_entries: std::slice::from_ref(&inception.log_entry),
                version_time: at + chrono::TimeDelta::days(1),
                current_root_seed: &current,
                next_root_public_key_multibase: &multikey(&[0x63; 32]),
                state: &inception.log_entry["state"],
            })
            .unwrap();
        let mut rotated = resolution(&did, &[inception.log_entry, rotation.log_entry]);
        assert!(
            verify_native_approval_jws(
                &rotated,
                &principal,
                payload,
                &proof(&old, &old_method, payload)
            )
            .is_err()
        );
        let valid = proof(&current, &current_method, payload);
        assert_eq!(
            verify_native_approval_jws(&rotated, &principal, payload, &valid).unwrap(),
            current_method
        );
        assert!(
            verify_native_approval_jws(&rotated, &principal, b"another target", &valid).is_err()
        );
        assert!(
            verify_native_approval_jws(
                &rotated,
                &principal,
                payload,
                &proof(&old, &current_method, payload)
            )
            .is_err()
        );
        assert!(
            verify_native_approval_jws(
                &rotated,
                &principal,
                payload,
                &proof(
                    &current,
                    &format!("did:key:{}#wrong", multikey(&current)),
                    payload
                )
            )
            .is_err()
        );
        assert!(
            verify_native_approval_jws(
                &rotated,
                &DidCoreId::new("ak:did_core:web:other.example").unwrap(),
                payload,
                &valid
            )
            .is_err()
        );
        rotated.identity_fact_rejection =
            Some(DidResolutionIdentityFactRejection::ControllerProofUnverified);
        assert!(verify_native_approval_jws(&rotated, &principal, payload, &valid).is_err());
        rotated.identity_fact_rejection = None;
        rotated.key_log_head = None;
        assert!(verify_native_approval_jws(&rotated, &principal, payload, &valid).is_err());
        rotated.closed_method_evidence = None;
        assert!(verify_native_approval_jws(&rotated, &principal, payload, &valid).is_err());
    }
}
