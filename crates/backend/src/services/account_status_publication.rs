//! Fail-closed scheduling boundary for account-status publication.

use arkret_event_draft::TypedEventDraft;
use arkret_models_collaboration::account_lifecycle::{
    AccountStatusAuthoringEventKind, AccountStatusAuthoringFrontiersRequestBody,
    AccountStatusInitialPublication, AccountStatusPublication, AccountStatusPublicationRequestBody,
    UnsignedAccountStatusAuthorityEvidence,
};
use arkret_models_collaboration::events_payloads::AccountStatusPayload;
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_wire::{DidCoreId, Hash, NonEmptyString, ScopeRef, event_spec};
use coauth_data::queue::{AccountStatusPublicationJob, QueueJobRepositoryExt as _};
use coauth_data::{
    BoxRepository, Clock, PrincipalDidBinding, RepositoryAccess as _, RepositoryError, User,
};
use rand_core::RngCore;
use thiserror::Error;

/// Errors that prevent a publication from entering the durable outbox.
#[derive(Debug, Error)]
pub enum AccountStatusPublicationError {
    #[error("account-status publication idempotency key is empty")]
    EmptyIdempotencyKey,
    #[error("account-status publication body is invalid: {0}")]
    InvalidBody(String),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Complete immutable publication selected before the local status mutation.
/// The audience is explicit because authority evidence deliberately does not
/// disclose a destination Principal Server.
pub struct AccountStatusPublicationPlan {
    pub audience: DidCoreId,
    pub destination_name: String,
    pub idempotency_key: String,
    pub body: AccountStatusPublicationRequestBody,
}

const AUTHORITY_EVIDENCE_TTL: chrono::Duration = chrono::Duration::minutes(5);

fn supersedes_for_transition(
    current_status: AccountStatus,
    target_status: AccountStatus,
    current_status_event_ids: &[arkret_wire::EventId],
) -> Result<Option<Vec<arkret_wire::EventId>>, AccountStatusPublicationError> {
    if !target_status.is_less_strict_than(current_status) {
        return Ok(None);
    }
    if current_status_event_ids.is_empty() {
        return Err(AccountStatusPublicationError::InvalidBody(
            "a less-strict status requires the complete current status frontier".to_owned(),
        ));
    }
    Ok(Some(current_status_event_ids.to_vec()))
}

/// Mint fresh transport authority, resolve authoritative frontiers and sign
/// the one exact Event that will be frozen in the durable outbox.
pub async fn author_transition_plan(
    principal_server: &dyn coauth_principal::ConnectorAdmin,
    keystore: &coauth_keystore::Keystore,
    service_id: &str,
    user: &User,
    binding: &PrincipalDidBinding,
    target_status: AccountStatus,
    now: chrono::DateTime<chrono::Utc>,
    rng: &mut (dyn RngCore + Send),
) -> Result<AccountStatusPublicationPlan, AccountStatusPublicationError> {
    let (destination_name, audience) = principal_server
        .account_status_destination()
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    if audience != binding.audience {
        return Err(AccountStatusPublicationError::InvalidBody(
            "configured destination does not match the durable binding audience".to_owned(),
        ));
    }
    let issuer_service_id = DidCoreId::new(service_id.to_owned())
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    if issuer_service_id != binding.binding_receipt.account_authority_id {
        return Err(AccountStatusPublicationError::InvalidBody(
            "runtime service identity does not match the accepted account authority".to_owned(),
        ));
    }
    let unsigned_evidence = UnsignedAccountStatusAuthorityEvidence {
        account_authority_id: binding.binding_receipt.account_authority_id.clone(),
        issuer_service_id: issuer_service_id.clone(),
        principal_control_realm_id: binding.principal_control_realm_id.clone(),
        account_id: NonEmptyString::new(user.id.to_string())
            .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?,
        principal_id: binding.principal_id.clone(),
        binding_version: binding.binding_version,
        issued_at: now,
        expires_at: now + AUTHORITY_EVIDENCE_TTL,
        verification_method: binding.binding_receipt.proof.verification_method.clone(),
    };
    let signing_seed = keystore
        .service_identity_seed()
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
    let authority_evidence =
        arkret_signatures::account_status::sign_account_status_authority_evidence(
            unsigned_evidence,
            &signing_key,
        )
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let signer_did = authority_evidence
        .proof
        .verification_method
        .as_str()
        .rsplit_once('#')
        .and_then(|(controller, _)| arkret_wire::DidFullId::new(controller.to_owned()).ok())
        .ok_or_else(|| {
            AccountStatusPublicationError::InvalidBody(
                "account authority verification method has no full DID controller".to_owned(),
            )
        })?;
    let event_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        signing_seed,
        signer_did,
        authority_evidence.proof.verification_method.clone(),
    );
    let frontier_request = AccountStatusAuthoringFrontiersRequestBody {
        authority_evidence: authority_evidence.clone(),
        event_kind: AccountStatusAuthoringEventKind::AccountStatus,
    };
    let frontiers = principal_server
        .account_status_authoring_frontiers(&destination_name, &frontier_request)
        .await
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    frontiers
        .validate_for_request(&frontier_request)
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;

    let supersedes_status_event_ids = supersedes_for_transition(
        user.status,
        target_status,
        &frontiers.current_status_event_ids,
    )?;
    let payload = AccountStatusPayload {
        account_id: user.id.to_string(),
        principal_id: binding.principal_id.clone(),
        status: target_status,
        reason_code: None,
        reason: None,
        effective_at: now,
        expires_at: None,
        supersedes_status_event_ids,
        admin_proof: None,
    };
    let mut secret = [0_u8; 32];
    rng.fill_bytes(&mut secret);
    let initial_ms = u64::try_from(now.timestamp_millis()).map_err(|_| {
        AccountStatusPublicationError::InvalidBody(
            "effective_at precedes the Unix epoch".to_owned(),
        )
    })?;
    let mut hlc_generator = arkret_hlc::HlcGenerator::with_initial_time(
        binding.principal_control_realm_id.as_str(),
        "coauth-account-authority",
        &secret,
        initial_ms,
    );
    let hlc = match frontiers.seal_frontier.hlc.as_ref() {
        Some(remote) => hlc_generator
            .generate_with_remote(remote)
            .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?,
        None => hlc_generator.generate(),
    };
    let mut event = TypedEventDraft::<event_spec::AccountStatus>::new(
        ScopeRef::Realm {
            realm_id: binding.principal_control_realm_id.clone(),
        },
        issuer_service_id,
        binding.audience.clone(),
        payload,
    )
    .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?
    .with_prev_refs(frontiers.actor_frontier.frontier_event_ids)
    .with_seal_basis(frontiers.seal_frontier.seal_basis())
    .author(frontiers.actor_frontier.next_actor_seq, hlc, now)
    .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    arkret_signatures::sign_event(
        &mut event,
        &event_signer,
        &authority_evidence.proof.verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let idempotency_key = format!("account-status:{}", event.event_id);
    let body = AccountStatusPublicationRequestBody {
        authority_evidence,
        publication: AccountStatusPublication::Initial(AccountStatusInitialPublication { event }),
        cba_proof_bundles: Vec::new(),
    };
    body.validate_shape()
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    Ok(AccountStatusPublicationPlan {
        audience,
        destination_name,
        idempotency_key,
        body,
    })
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::objects::account_status::AccountStatus;
    use arkret_wire::EventId;

    use super::supersedes_for_transition;

    fn event_id(seed: char) -> EventId {
        EventId::new(match seed {
            'A' => "ak:event:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934",
            _ => "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6",
        })
        .unwrap()
    }

    #[test]
    fn lowering_status_requires_and_copies_the_complete_current_frontier() {
        assert!(
            supersedes_for_transition(AccountStatus::Suspended, AccountStatus::Active, &[],)
                .is_err()
        );

        let current_heads = vec![event_id('A'), event_id('B')];
        assert_eq!(
            supersedes_for_transition(
                AccountStatus::Suspended,
                AccountStatus::Active,
                &current_heads,
            )
            .unwrap(),
            Some(current_heads)
        );
    }

    #[test]
    fn stricter_status_does_not_claim_to_supersede_current_heads() {
        assert_eq!(
            supersedes_for_transition(
                AccountStatus::Active,
                AccountStatus::Suspended,
                &[event_id('A')],
            )
            .unwrap(),
            None
        );
    }
}

/// Bind an authored publication to the exact durable account/PCR authority
/// basis and requested local transition before either can be committed.
pub fn validate_transition_plan(
    user: &User,
    binding: &PrincipalDidBinding,
    target_status: AccountStatus,
    plan: &AccountStatusPublicationPlan,
) -> Result<(), AccountStatusPublicationError> {
    plan.body
        .validate_shape()
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let evidence = &plan.body.authority_evidence;
    if binding.user_id != user.id
        || binding.audience != plan.audience
        || binding.principal_id != evidence.principal_id
        || binding.principal_control_realm_id != evidence.principal_control_realm_id
        || binding.binding_version != evidence.binding_version
        || binding.binding_receipt.account_authority_id != evidence.account_authority_id
        || evidence.account_id.as_str() != user.id.to_string()
    {
        return Err(AccountStatusPublicationError::InvalidBody(
            "publication does not match the durable account/PCR authority basis".to_owned(),
        ));
    }
    let payload = serde_json::from_value::<AccountStatusPayload>(serde_json::Value::Object(
        plan.body
            .publication
            .event()
            .payload
            .clone()
            .into_iter()
            .collect(),
    ))
    .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    if payload.status != target_status {
        return Err(AccountStatusPublicationError::InvalidBody(
            "publication status does not match the committed local transition".to_owned(),
        ));
    }
    Ok(())
}

/// Validate and atomically enqueue one immutable destination-scoped body.
///
/// Callers must author the complete signed Event and authority evidence before
/// entering this boundary. The queue worker retries these exact bytes; it never
/// rebuilds a body from mutable account state.
pub async fn enqueue_exact_publication(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    destination_name: &str,
    idempotency_key: &str,
    body: AccountStatusPublicationRequestBody,
) -> Result<Hash, AccountStatusPublicationError> {
    if destination_name.trim().is_empty() {
        return Err(AccountStatusPublicationError::InvalidBody(
            "destination Principal Server name is empty".to_owned(),
        ));
    }
    if idempotency_key.trim().is_empty() {
        return Err(AccountStatusPublicationError::EmptyIdempotencyKey);
    }
    body.validate_shape()
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let body_digest = Hash::new(
        arkret_canonical::canonical_sha256(&body)
            .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?,
    )
    .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let job = AccountStatusPublicationJob::new(
        destination_name.to_owned(),
        idempotency_key.to_owned(),
        body_digest.clone(),
        body,
    );
    repo.queue_job().schedule_job(rng, clock, job).await?;
    Ok(body_digest)
}
