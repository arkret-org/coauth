//! Canonical account-first handoff, lease, and identity-binding operations.

use arkret_core::error::{
    ERROR_CODE_AUDIENCE_MISMATCH, ERROR_CODE_DUPLICATE_CONFLICT, ERROR_CODE_FAILED_PRECONDITION,
    ERROR_CODE_INVALID_SIGNATURE, ERROR_CODE_UNAUTHENTICATED,
};
use arkret_core::{
    ACCOUNT_HANDOFF_ALLOWED_OPERATIONS, AccountHandoffAllowedOperation, AccountHandoffBinding,
    AccountHandoffOutcome, AccountHandoffRequestBody, IdentityBindingChallengeRequestBody,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::Duration;
use coauth_data::{
    AccountHandoffCreation, AccountHandoffGrant, AccountHandoffGrantInput,
    IdentityBindingChallengeInput, IdentityBindingChallengeIssue, RepositoryAccess as _, new_id,
};
use rand_core::RngCore;
use salvo::prelude::*;

use super::session_grant::map_oidc_exchange_error;
use super::{ArkretRouteError, DepotExt};
use crate::handlers::account::auth::oidc_bridge::{
    OidcCodeExchangeInput, exchange_oidc_code_for_account_handoff,
};
use crate::handlers::account::auth::{DpopSessionBinding, extract_dpop_binding_for_kickoff};
use crate::handlers::{make_clock, make_rng};
use crate::services::dpop::{DpopVerification, dpop_header_from_request, dpop_htu};

const HANDOFF_TTL: Duration = Duration::minutes(10);
const IDENTITY_CREATION_LEASE_TTL: Duration = Duration::minutes(15);
const IDENTITY_BINDING_CHALLENGE_TTL: Duration = Duration::minutes(5);

/// `POST /_arkret/gate/account/authentication-handoffs`.
#[handler]
pub async fn create_account_handoff(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<AccountHandoffOutcome>, ArkretRouteError> {
    if req.headers().contains_key(http::header::AUTHORIZATION) {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_UNAUTHENTICATED,
            "account handoff creation must not carry an Authorization credential",
        ));
    }
    let url_builder = depot.url_builder()?;
    let dpop_binding = extract_dpop_binding_for_kickoff(req, depot, &url_builder)
        .await
        .map_err(|error| proof_invalid(format!("invalid account-handoff DPoP proof: {error}")))?
        .ok_or_else(|| proof_invalid("account handoff creation requires a DPoP proof"))?;
    let body: AccountHandoffRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    let request_digest = body
        .canonical_request_digest()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    if body.proof.request_canonical_digest != request_digest {
        return Err(proof_invalid(
            "account handoff request_canonical_digest does not match the canonical request",
        ));
    }
    verify_handoff_holder_signature(&body, &dpop_binding)?;
    if body.proof.challenge != body.proof.nonce {
        return Err(proof_invalid(
            "account handoff challenge does not match the authorization transaction nonce",
        ));
    }

    let clock = make_clock();
    let now = clock.now();
    let mut replay_repo = depot.repo().await?;
    let existing = replay_repo
        .account_handoff()
        .get_by_request_id(&body.request_id)
        .await?;
    if let Some(existing) = existing {
        let creation =
            if existing.request_digest == request_digest && existing.cnf_jkt == dpop_binding.jkt {
                replay_repo
                    .account_handoff()
                    .resolve_creation(&existing, now)
                    .await?
            } else {
                AccountHandoffCreation::DuplicateConflict
            };
        replay_repo.cancel().await.ok();
        return creation_to_outcome(creation).map(Json);
    }
    replay_repo.cancel().await.ok();

    let proof = &body.proof;
    let input = OidcCodeExchangeInput {
        authorization_code: proof.authorization_code.clone(),
        code_verifier: proof.code_verifier.clone(),
        redirect_uri: proof.redirect_uri.clone(),
        issuer: proof.issuer.clone(),
        client_id: proof.client_id.clone(),
        state: proof.state.clone(),
        nonce: proof.nonce.clone(),
        device_id: String::new(),
        expected_principal_id: String::new(),
        requested_audience: Some(proof.audience.to_string()),
    };
    let authenticated =
        exchange_oidc_code_for_account_handoff(req, depot, dpop_binding.clone(), input)
            .await
            .map_err(map_oidc_exchange_error)?;
    if authenticated.audience != proof.audience.as_str() {
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_AUDIENCE_MISMATCH,
            "authenticated handoff audience does not match the request proof",
        ));
    }

    let mut rng = make_rng();
    let mut repo = depot.repo().await?;
    let creation = repo
        .account_handoff()
        .create_with_lease(AccountHandoffGrantInput {
            id: new_id(now, &mut *rng),
            request_id: body.request_id,
            request_digest,
            service_account_id: authenticated.user.id,
            browser_session_id: authenticated.browser_session_id,
            audience: authenticated.audience,
            cnf_jkt: dpop_binding.jkt,
            account_handoff_grant: random_opaque(&mut *rng, 32),
            issued_at: now,
            expires_at: now + HANDOFF_TTL,
            lease_id: random_opaque(&mut *rng, 24),
            lease_expires_at: now + IDENTITY_CREATION_LEASE_TTL,
        })
        .await?;
    repo.save().await?;
    creation_to_outcome(creation).map(Json)
}

/// `POST /_arkret/gate/account/identity-binding-challenges`.
#[handler]
pub async fn issue_identity_binding_challenge(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<arkret_core::IdentityBindingChallengeOutcome>, ArkretRouteError> {
    let (grant, _dpop) = authenticate_account_handoff(
        req,
        depot,
        AccountHandoffAllowedOperation::IssueIdentityBindingChallenge,
    )
    .await?;
    enforce_handoff_operation(
        &grant,
        AccountHandoffAllowedOperation::IssueIdentityBindingChallenge,
    )?;
    let body: IdentityBindingChallengeRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    let request_digest = body
        .canonical_request_digest()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let validated =
        arkret_signatures::webvh::validate_principal_inception_operation(&body.did_operation)
            .map_err(|error| failed_precondition(error.to_string()))?;
    if validated.document_profile
        != arkret_signatures::webvh::PrincipalDidDocumentProfile::ExternalAuthority
    {
        return Err(failed_precondition(
            "account-first identity creation requires the external enrollment-authority B model",
        ));
    }
    let key_store = depot.key_store()?;
    let enrollment_authority =
        crate::services::device_enrollment_authority::enrollment_authority(&key_store)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let expected_authority = enrollment_authority.did();
    if validated
        .enrollment_authority
        .as_ref()
        .map(arkret_core::Did::as_str)
        != Some(expected_authority)
    {
        return Err(failed_precondition(
            "principal inception enrollment authority does not match the deployment pin",
        ));
    }

    let arkret_config = depot.arkret_config()?;
    let trust_domain = arkret_config
        .trust_domain
        .as_deref()
        .ok_or_else(|| failed_precondition("deployment trust_domain is not configured"))?;
    let trust_domain = arkret_core::TypedTrustDomainId::new(trust_domain.to_owned())
        .map_err(|error| failed_precondition(error.to_string()))?;
    let audience = arkret_core::Did::new(grant.audience.clone())
        .map_err(|error| failed_precondition(error.to_string()))?;
    let origin = depot
        .url_builder()?
        .http_base()
        .origin()
        .ascii_serialization();
    let clock = make_clock();
    let now = clock.now();
    let mut rng = make_rng();
    let mut repo = depot.repo().await?;
    let issue = repo
        .account_handoff()
        .reserve_and_issue_challenge(IdentityBindingChallengeInput {
            request_id: body.request_id,
            request_digest,
            service_account_id: grant.service_account_id,
            audience: grant.audience.clone(),
            lease_id: body.lease_id,
            lease_fence: body.lease_fence,
            holder_jkt: grant.cnf_jkt.clone(),
            did_operation: body.did_operation,
            operation_digest: validated.operation_digest,
            challenge_id: random_opaque(&mut *rng, 24),
            challenge: random_opaque(&mut *rng, 32),
            origin,
            trust_domain,
            issued_at: now,
            expires_at: now + IDENTITY_BINDING_CHALLENGE_TTL,
            lease_expires_at: now + IDENTITY_CREATION_LEASE_TTL,
        })
        .await?;
    match issue {
        IdentityBindingChallengeIssue::Issued(challenge)
        | IdentityBindingChallengeIssue::Replay(challenge) => {
            repo.save().await?;
            let outcome = challenge.wire_outcome();
            if outcome.audience != audience {
                return Err(failed_precondition(
                    "persisted challenge audience does not match the handoff",
                ));
            }
            Ok(Json(outcome))
        }
        IdentityBindingChallengeIssue::DuplicateConflict
        | IdentityBindingChallengeIssue::ReservationConflict => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                ERROR_CODE_DUPLICATE_CONFLICT,
                "request or identity reservation conflicts with durable state",
            ))
        }
        IdentityBindingChallengeIssue::LeaseMismatch
        | IdentityBindingChallengeIssue::StaleRequest => {
            repo.cancel().await.ok();
            Err(failed_precondition(
                "identity-creation lease, fence, holder, or challenge request is stale",
            ))
        }
    }
}

pub(crate) async fn authenticate_account_handoff(
    req: &Request,
    depot: &Depot,
    operation: AccountHandoffAllowedOperation,
) -> Result<(AccountHandoffGrant, DpopVerification), ArkretRouteError> {
    let token = account_handoff_authorization(req)?;
    let now = chrono::Utc::now();
    let mut repo = depot.repo().await?;
    let grant = repo
        .account_handoff()
        .get_active_by_token(token, now)
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                ERROR_CODE_UNAUTHENTICATED,
                "account handoff is expired, revoked, consumed, or unknown",
            )
        })?;
    enforce_handoff_operation(&grant, operation)?;
    repo.cancel().await.ok();

    let dpop = dpop_header_from_request(req)
        .ok_or_else(|| proof_invalid("account handoff request requires a DPoP proof"))?;
    let htu = dpop_htu(&depot.url_builder()?.http_base(), req);
    let verification = depot
        .dpop_verifier()?
        .verify(&dpop, req.method().as_str(), &htu, now, Some(token))
        .await
        .map_err(|error| proof_invalid(format!("account handoff DPoP proof failed: {error}")))?;
    if verification.jkt != grant.cnf_jkt {
        return Err(proof_invalid(
            "account handoff DPoP key does not match the credential cnf.jkt",
        ));
    }
    Ok((grant, verification))
}

pub(crate) fn enforce_handoff_operation(
    grant: &AccountHandoffGrant,
    operation: AccountHandoffAllowedOperation,
) -> Result<(), ArkretRouteError> {
    if grant.allowed_operations != ACCOUNT_HANDOFF_ALLOWED_OPERATIONS
        || !grant.allowed_operations.contains(&operation)
    {
        return Err(ArkretRouteError::Forbidden(
            "account handoff does not authorize this operation".to_owned(),
        ));
    }
    Ok(())
}

fn account_handoff_authorization(req: &Request) -> Result<&str, ArkretRouteError> {
    let value = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                ERROR_CODE_UNAUTHENTICATED,
                "Authorization: DPoP <account_handoff_grant> is required",
            )
        })?;
    let (scheme, token) = value.split_once(' ').ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_UNAUTHENTICATED,
            "account handoff Authorization header is malformed",
        )
    })?;
    if !scheme.eq_ignore_ascii_case("DPoP")
        || token.is_empty()
        || token.contains(char::is_whitespace)
    {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_UNAUTHENTICATED,
            "account handoff requires the DPoP authorization scheme",
        ));
    }
    Ok(token)
}

fn verify_handoff_holder_signature(
    body: &AccountHandoffRequestBody,
    dpop_binding: &DpopSessionBinding,
) -> Result<(), ArkretRouteError> {
    let jwk = serde_json::to_value(&dpop_binding.public_jwk)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let public_key = arkret_signatures::proof::PublicKeyMaterial::Jwk { value: jwk };
    let signing_bytes = body
        .proof
        .canonical_signing_bytes()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    if !arkret_signatures::proof::verify_detached_ed25519_signature(
        &public_key,
        &signing_bytes,
        &body.proof.signature,
    ) {
        return Err(proof_invalid(
            "account handoff holder signature is not valid for the DPoP Ed25519 key",
        ));
    }
    Ok(())
}

fn creation_to_outcome(
    creation: AccountHandoffCreation,
) -> Result<AccountHandoffOutcome, ArkretRouteError> {
    let (grant, binding) = match creation {
        AccountHandoffCreation::Active { grant, lease } => (
            grant,
            AccountHandoffBinding::IdentityCreationActive {
                identity_creation_lease: lease.wire_lease(),
            },
        ),
        AccountHandoffCreation::Busy {
            grant,
            retry_after_ms,
        } => (
            grant,
            AccountHandoffBinding::IdentityCreationBusy { retry_after_ms },
        ),
        AccountHandoffCreation::Bound {
            grant,
            principal_id,
        } => (grant, AccountHandoffBinding::Bound { principal_id }),
        AccountHandoffCreation::DuplicateConflict => {
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                ERROR_CODE_DUPLICATE_CONFLICT,
                "request_id was reused with different canonical request bytes",
            ));
        }
        AccountHandoffCreation::ExpiredReplay => {
            return Err(ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                ERROR_CODE_UNAUTHENTICATED,
                "the replayed account handoff request is no longer live",
            ));
        }
    };
    let outcome = AccountHandoffOutcome {
        request_id: grant.request_id,
        account_handoff_grant: grant.account_handoff_grant,
        expires_at: grant.expires_at,
        allowed_operations: grant.allowed_operations,
        binding,
    };
    outcome
        .validate()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    Ok(outcome)
}

fn random_opaque(rng: &mut (impl RngCore + ?Sized), bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rng.fill_bytes(&mut value);
    Base64UrlUnpadded::encode_string(&value)
}

fn proof_invalid(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        ERROR_CODE_INVALID_SIGNATURE,
        format!("reason_code=proof_invalid; {}", message.into()),
    )
}

fn failed_precondition(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        ERROR_CODE_FAILED_PRECONDITION,
        message,
    )
}
