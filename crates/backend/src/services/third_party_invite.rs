//! Deployment-private IVS custody. Wire DTOs and transcripts belong to the SDK.
//! Callers authenticate before entering this module and commit its repository
//! transaction before exposing a result. No function authors a Realm Event.

use arkret_models_collaboration::governance::membership_invite::{
    InviteClaimBindingProof, InviteClaimBindingProofBody,
};
use arkret_models_collaboration::governance::third_party_invite::*;
use arkret_wire::{Did, DidUrl, Hash};
use chrono::{DateTime, Duration, Utc};
use coauth_data::storage::third_party_invite::PrivateInviteRecord;
use coauth_data::{BoxRepository, RepositoryAccess};
use coauth_keyring::Encrypter;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};
pub(crate) mod authentication;
mod runtime;
#[cfg(test)]
mod tests;
pub use runtime::ThirdPartyInviteRuntime;

/// Deliberately opaque errors: no raw request, 3PID, token or crypto failure detail.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InviteError {
    #[error("third-party invite unavailable")]
    NotFound,
    #[error("original invite intent differs")]
    DuplicateConflict,
    #[error("invite provisioning is already bound")]
    AlreadyBound,
    #[error("acceptance attestation is stale")]
    AcceptanceStale,
    #[error("invite provisioning activation expired")]
    ProvisioningExpired,
    #[error("accepted invite material differs")]
    MaterialMismatch,
    #[error("invitation issuance rate exceeded")]
    RateLimited,
    #[error("unactivated invite quota exceeded")]
    QuotaExceeded,
    #[error("delivery scheme is unsupported")]
    UnsupportedFeature,
    #[error("private invite custody failed")]
    Internal,
}
impl From<coauth_data::RepositoryError> for InviteError {
    fn from(_: coauth_data::RepositoryError) -> Self {
        Self::Internal
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SecretMaterial {
    pub token: String,
    pub salt: [u8; 32],
    pub pepper: [u8; 32],
    pub signing_seed: [u8; 32],
    pub delivery_target: String,
}
impl Drop for SecretMaterial {
    fn drop(&mut self) {
        self.token.zeroize();
        self.salt.zeroize();
        self.pepper.zeroize();
        self.signing_seed.zeroize();
        self.delivery_target.zeroize();
    }
}

/// Only serialized inside the existing service AEAD cipher. This is not a wire DTO.
#[derive(Serialize, Deserialize)]
pub(crate) struct Custody {
    pub public: ThirdPartyInviteProvisionOutcome,
    pub activation: Option<ThirdPartyInviteActivationOutcome>,
    pub activation_digest: Option<String>,
    pub invite_digest: Option<Hash>,
    pub verification_method: DidUrl,
    pub state: ThirdPartyInviteProvisioningState,
    pub delivery_state: Option<ThirdPartyInviteDeliveryState>,
    pub delivery_attempts: u32,
    pub failed_lookup_attempts: u32,
    pub token_mac: String,
    /// Salted target digest remains only in encrypted provider audit custody.
    pub delivery_target_digest: String,
    pub secrets: Option<SecretMaterial>,
}

pub(crate) fn digest(bytes: impl AsRef<[u8]>) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn random_bytes(rng: &mut dyn RngCore) -> [u8; 32] {
    let mut b = [0; 32];
    rng.fill_bytes(&mut b);
    b
}
// No 0/O/1/I/L. Rejection sampling preserves uniform draws.
fn random_code(rng: &mut dyn RngCore, len: usize) -> String {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    (0..len)
        .map(|_| {
            loop {
                let b = rng.next_u32();
                let zone = u32::MAX - u32::MAX % (ALPHABET.len() as u32);
                if b < zone {
                    break ALPHABET[(b % (ALPHABET.len() as u32)) as usize] as char;
                }
            }
        })
        .collect()
}
fn token_mac(pepper: &[u8; 32], token: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pepper).expect("fixed HMAC key");
    mac.update(token.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
pub(crate) fn token_selector(token: &str) -> String {
    // Lookup namespace is explicit in the issued code, not inferred from length.
    if let Some((namespace, _)) = token.split_once('_') {
        if namespace.len() == 16 {
            return format!("lookup:{namespace}");
        }
    }
    format!("offline:{}", digest(token))
}

pub(crate) fn decrypt(
    row: &PrivateInviteRecord,
    encrypter: &Encrypter,
) -> Result<Custody, InviteError> {
    let bytes = Zeroizing::new(
        encrypter
            .decrypt_string(&row.encrypted_record)
            .map_err(|_| InviteError::Internal)?,
    );
    let c: Custody = serde_json::from_slice(&bytes).map_err(|_| InviteError::Internal)?;
    if digest(c.public.provisioning_id.as_str()) != row.handle_digest
        || digest(
            arkret_canonical::canonical_json_bytes(&c.public.inviter_account_id)
                .map_err(|_| InviteError::Internal)?,
        ) != row.issuer_digest
        || digest(c.public.realm_id.as_str()) != row.realm_digest
        || c.public.expires_at != row.expires_at
        || c.public.activation_expires_at != row.activation_expires_at
    {
        return Err(InviteError::Internal);
    }
    Ok(c)
}
fn encrypt(c: &Custody, encrypter: &Encrypter) -> Result<String, InviteError> {
    let bytes = Zeroizing::new(serde_json::to_vec(c).map_err(|_| InviteError::Internal)?);
    encrypter
        .encrypt_to_string(&bytes)
        .map_err(|_| InviteError::Internal)
}

pub(crate) async fn update(
    repo: &mut BoxRepository,
    mut row: PrivateInviteRecord,
    c: &Custody,
    encrypter: &Encrypter,
) -> Result<(), InviteError> {
    row.encrypted_record = encrypt(c, encrypter)?;
    row.state = serde_json::to_value(c.state)
        .map_err(|_| InviteError::Internal)?
        .as_str()
        .ok_or(InviteError::Internal)?
        .to_owned();
    if c.secrets.is_none() {
        row.token_selector = None;
        row.deliver_after = None;
    }
    repo.third_party_invite().update(row).await?;
    Ok(())
}

pub(crate) fn delivery_address(
    target: &str,
) -> Result<coauth_messaging::email::Address, InviteError> {
    let mailbox = target
        .strip_prefix("mailto:")
        .ok_or(InviteError::UnsupportedFeature)?;
    // No caller-selected mail headers, URI fragments or alternate channels.
    if mailbox.contains(['?', '#']) {
        return Err(InviteError::UnsupportedFeature);
    }
    let encoded = format!(
        "address={}",
        mailbox.replace('+', "%2B").replace('&', "%26")
    );
    let address = url::form_urlencoded::parse(encoded.as_bytes())
        .next()
        .ok_or(InviteError::NotFound)?
        .1;
    address.parse().map_err(|_| InviteError::NotFound)
}

pub(crate) async fn provision_verified(
    repo: &mut BoxRepository,
    encrypter: &Encrypter,
    rng: &mut (dyn RngCore + Send),
    request: &ThirdPartyInviteProvisionRequestBody,
    service_did: &Did,
    source_ip_bucket: &str,
    now: DateTime<Utc>,
) -> Result<ThirdPartyInviteProvisionOutcome, InviteError> {
    // Public canonical timestamps and PostgreSQL must retain identical cuts.
    let now = arkret_canonical::normalize_timestamp_canonical(now);
    let issuer = digest(
        arkret_canonical::canonical_json_bytes(&request.inviter_account_id)
            .map_err(|_| InviteError::Internal)?,
    );
    let realm = digest(request.realm_id.as_str());
    let intent = request
        .payload_digest()
        .map_err(|_| InviteError::NotFound)?
        .to_string();
    repo.third_party_invite()
        .lock_namespace(&format!("ivs:issuer:{issuer}"))
        .await?;
    if let Some(row) = repo
        .third_party_invite()
        .find_request(&issuer, request.request_id.as_str())
        .await?
    {
        if row.intent_digest != intent {
            return Err(InviteError::DuplicateConflict);
        }
        let c = decrypt(&row, encrypter)?;
        // Retained terminal records obey the original intent ledger too.
        // Returning frozen public material never restores secret custody,
        // lifecycle state, delivery intent, or the active token selector.
        return Ok(c.public);
    }
    let delivery_target = request.delivery_target_uri.clone().into_inner();
    delivery_address(&delivery_target)?;
    if request.expires_at <= now {
        return Err(InviteError::NotFound);
    }
    let bucket = digest(format!("provision:{issuer}:{realm}:{source_ip_bucket}"));
    let minute = DateTime::from_timestamp(now.timestamp().div_euclid(60) * 60, 0)
        .ok_or(InviteError::Internal)?;
    if !repo
        .third_party_invite()
        .take_rate(&bucket, minute, 5)
        .await?
    {
        return Err(InviteError::RateLimited);
    }
    if repo
        .third_party_invite()
        .unactivated_count(&issuer, &realm, now)
        .await?
        >= 16
    {
        return Err(InviteError::QuotaExceeded);
    }
    let handle = ThirdPartyInviteProvisioningId::new(format!(
        "{THIRD_PARTY_INVITE_PROVISIONING_ID_PREFIX}{}",
        arkret_canonical::base64url_encode(random_bytes(rng))
    ))
    .map_err(|_| InviteError::Internal)?;
    let namespace = random_code(rng, 16);
    let token = match request.oob_code_kind {
        ThirdPartyInviteOobKind::OfflineToken => random_code(rng, 40),
        ThirdPartyInviteOobKind::Lookup => format!("{namespace}_{}", random_code(rng, 8)),
    };
    let salt = random_bytes(rng);
    let pepper = random_bytes(rng);
    let signing_seed = random_bytes(rng);
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let mut commitment = Sha256::new();
    commitment.update(salt);
    commitment.update(token.as_bytes());
    let commitment = Hash::new(format!("sha256:{:x}", commitment.finalize()))
        .map_err(|_| InviteError::Internal)?;
    let key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &signing_key.verifying_key().to_bytes(),
    );
    let public = ThirdPartyInviteProvisionOutcome {
        provisioning_id: handle,
        realm_id: request.realm_id.clone(),
        inviter_account_id: request.inviter_account_id.clone(),
        expires_at: request.expires_at.min(now + Duration::hours(24)),
        activation_expires_at: request.expires_at.min(now + Duration::minutes(15)),
        third_party_invite: ThirdPartyInvite {
            oob_code_kind: request.oob_code_kind,
            display_name_hint: None,
            token_commitment: Some(commitment),
            max_claims: 1,
            token_salt_id: (request.oob_code_kind == ThirdPartyInviteOobKind::OfflineToken)
                .then(|| format!("salt-{namespace}")),
            token_entropy_bits: (request.oob_code_kind == ThirdPartyInviteOobKind::OfflineToken)
                .then_some(196),
            lookup_table_ref: (request.oob_code_kind == ThirdPartyInviteOobKind::Lookup)
                .then(|| namespace.clone()),
            pepper_id: (request.oob_code_kind == ThirdPartyInviteOobKind::Lookup)
                .then(|| format!("pepper-{namespace}")),
            verification_id: request.verification_id.clone(),
            verification_public_key: key,
        },
    };
    public
        .validate_for_request(request)
        .map_err(|_| InviteError::Internal)?;
    let mut target_digest = Sha256::new();
    target_digest.update(salt);
    target_digest.update(delivery_target.as_bytes());
    let custody = Custody {
        verification_method: DidUrl::new(format!("{service_did}#invite-{namespace}"))
            .map_err(|_| InviteError::Internal)?,
        token_mac: token_mac(&pepper, &token),
        delivery_target_digest: format!("sha256:{:x}", target_digest.finalize()),
        public: public.clone(),
        activation: None,
        activation_digest: None,
        invite_digest: None,
        state: ThirdPartyInviteProvisioningState::Provisioned,
        delivery_state: None,
        delivery_attempts: 0,
        failed_lookup_attempts: 0,
        secrets: Some(SecretMaterial {
            token,
            salt,
            pepper,
            signing_seed,
            delivery_target,
        }),
    };
    let token_selector = token_selector(&custody.secrets.as_ref().expect("minted").token);
    let row = PrivateInviteRecord {
        handle_digest: digest(public.provisioning_id.as_str()),
        issuer_digest: issuer,
        realm_digest: realm,
        request_id: request.request_id.to_string(),
        intent_digest: intent,
        encrypted_record: encrypt(&custody, encrypter)?,
        token_selector: Some(token_selector),
        state: "provisioned".to_owned(),
        expires_at: public.expires_at,
        activation_expires_at: public.activation_expires_at,
        deliver_after: None,
    };
    if !repo.third_party_invite().insert(row).await? {
        return Err(InviteError::DuplicateConflict);
    }
    Ok(public)
}

pub(crate) async fn activate_verified(
    repo: &mut BoxRepository,
    encrypter: &Encrypter,
    request: &ThirdPartyInviteActivationRequestBody,
    now: DateTime<Utc>,
) -> Result<ThirdPartyInviteActivationOutcome, InviteError> {
    let now = arkret_canonical::normalize_timestamp_canonical(now);
    let mut row = repo
        .third_party_invite()
        .find(&digest(request.provisioning_id.as_str()))
        .await?
        .ok_or(InviteError::NotFound)?;
    let mut c = decrypt(&row, encrypter)?;
    let activation_digest =
        digest(arkret_canonical::canonical_json_bytes(request).map_err(|_| InviteError::NotFound)?);
    if let Some(original) = &c.activation {
        if c.activation_digest.as_ref() == Some(&activation_digest) {
            return Ok(original.clone());
        }
        return Err(InviteError::AlreadyBound);
    }
    if c.state != ThirdPartyInviteProvisioningState::Provisioned {
        return Err(InviteError::NotFound);
    }
    if now >= c.public.activation_expires_at {
        c.state = ThirdPartyInviteProvisioningState::Expired;
        c.secrets = None;
        update(repo, row, &c, encrypter).await?;
        return Err(InviteError::ProvisioningExpired);
    }
    let a = &request.acceptance_attestation;
    a.validate_freshness(now)
        .map_err(|_| InviteError::AcceptanceStale)?;
    if a.inviter_account_id != c.public.inviter_account_id
        || a.realm_id != c.public.realm_id
        || a.third_party_invite != c.public.third_party_invite
        || a.invite_expires_at != c.public.expires_at
        || a.provisioning_id != c.public.provisioning_id
    {
        return Err(InviteError::MaterialMismatch);
    }
    let outcome = ThirdPartyInviteActivationOutcome {
        provisioning_id: request.provisioning_id.clone(),
        realm_id: a.realm_id.clone(),
        invite_id: a.invite_id.clone(),
        activated_at: now,
    };
    c.invite_digest = Some(a.invite_digest().map_err(|_| InviteError::NotFound)?);
    c.activation = Some(outcome.clone());
    c.activation_digest = Some(activation_digest);
    c.state = ThirdPartyInviteProvisioningState::Activated;
    c.delivery_state = Some(ThirdPartyInviteDeliveryState::Queued);
    row.deliver_after = Some(now);
    update(repo, row, &c, encrypter).await?;
    Ok(outcome)
}

pub(crate) fn status(c: &Custody) -> ThirdPartyInviteProvisioningStatusOutcome {
    ThirdPartyInviteProvisioningStatusOutcome {
        provisioning_id: c.public.provisioning_id.clone(),
        realm_id: c.public.realm_id.clone(),
        provisioning_state: c.state,
        invite_id: c.activation.as_ref().map(|a| a.invite_id.clone()),
        activated_at: c.activation.as_ref().map(|a| a.activated_at),
        delivery_state: c.delivery_state,
        delivery_attempt_count: c.activation.as_ref().map(|_| c.delivery_attempts),
        expires_at: c.public.expires_at,
        activation_expires_at: c.public.activation_expires_at,
    }
}

/// Verify a stored token without comparing secret strings. Mode comes from custody.
pub(crate) fn matches_token(c: &Custody, token: &str) -> bool {
    let Some(secret) = &c.secrets else {
        return false;
    };
    let Ok(expected) = hex::decode(&c.token_mac) else {
        return false;
    };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret.pepper).expect("fixed HMAC key");
    mac.update(token.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

/// Called only after the separate current authority guard has been acquired.
pub(crate) async fn consume_locked(
    repo: &mut BoxRepository,
    row: PrivateInviteRecord,
    mut c: Custody,
    encrypter: &Encrypter,
    request: &ThirdPartyInvitePresentRequestBody,
    now: DateTime<Utc>,
) -> Result<ThirdPartyInvitePresentOutcome, InviteError> {
    if c.state != ThirdPartyInviteProvisioningState::Activated
        || now >= c.public.expires_at
        || request.realm_id != c.public.realm_id
        || request.validate_minimal().is_err()
        || !matches_token(&c, &request.invite_token)
    {
        if c.public.third_party_invite.oob_code_kind == ThirdPartyInviteOobKind::Lookup
            && c.state == ThirdPartyInviteProvisioningState::Activated
        {
            c.failed_lookup_attempts += 1;
            if c.failed_lookup_attempts >= 3 {
                c.state = ThirdPartyInviteProvisioningState::Revoked;
                c.secrets = None;
            }
            update(repo, row, &c, encrypter).await?;
        }
        return Err(InviteError::NotFound);
    }
    let activation = c.activation.as_ref().ok_or(InviteError::Internal)?;
    let commitment = c
        .public
        .third_party_invite
        .token_commitment
        .clone()
        .ok_or(InviteError::Internal)?;
    let mut proof = InviteClaimBindingProof::new(
        c.public.third_party_invite.verification_id.clone(),
        request.subject_account_id.clone(),
        request.realm_id.clone(),
        &request.claim_nonce,
        arkret_canonical::format_timestamp_canonical(c.public.expires_at),
        c.verification_method.clone(),
        "unsigned",
    );
    let body = InviteClaimBindingProofBody::new(
        &proof,
        activation.invite_id.clone(),
        commitment.clone(),
        c.invite_digest.clone().ok_or(InviteError::Internal)?,
    )
    .map_err(|_| InviteError::Internal)?;
    let secret = c.secrets.as_ref().ok_or(InviteError::NotFound)?;
    proof.signature = arkret_canonical::base64url_encode(
        SigningKey::from_bytes(&secret.signing_seed)
            .sign(&body.canonical_bytes().map_err(|_| InviteError::Internal)?)
            .to_bytes(),
    );
    let outcome = ThirdPartyInvitePresentOutcome {
        invite_id: activation.invite_id.clone(),
        token_commitment: commitment,
        binding_proof: proof,
    };
    c.state = ThirdPartyInviteProvisioningState::Consumed;
    c.secrets = None;
    // No optional proof replay window: consumed input is always exhausted.
    update(repo, row, &c, encrypter).await?;
    Ok(outcome)
}
