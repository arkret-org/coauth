// Copyright (c) 2026 Arkret Authors.
//
// SPDX-License-Identifier: AGPL-3.0-only

pub mod registry;

use std::collections::HashSet;
use std::sync::Arc;

pub use self::registry::ConnectorRegistry;

#[derive(Debug)]
pub struct ConnectorAccountProfile {
    pub displayname: Option<String>,
    pub avatar_url: Option<String>,
    pub deactivated: bool,
}

/// Represents an optional mutation for a user profile field during
/// provisioning. Each variant captures whether the caller wants to
/// leave the field alone, assign a value, or clear it.
#[derive(Debug, Default)]
enum FieldUpdate<T> {
    #[default]
    Unchanged,
    Assign(T),
    Clear,
}

pub struct ConnectorProvisionRequest {
    handle: String,
    sub: String,
    displayname: FieldUpdate<String>,
    avatar_url: FieldUpdate<String>,
    emails: FieldUpdate<Vec<String>>,
    admin: bool,
}

impl ConnectorProvisionRequest {
    /// Create a new [`ConnectorProvisionRequest`].
    ///
    /// # Parameters
    ///
    /// * `handle` - The handle of the user to provision.
    /// * `sub` - The `sub` of the user, aka the internal ID.
    #[must_use]
    pub fn new(handle: impl Into<String>, sub: impl Into<String>) -> Self {
        Self {
            handle: handle.into(),
            sub: sub.into(),
            displayname: FieldUpdate::default(),
            avatar_url: FieldUpdate::default(),
            emails: FieldUpdate::default(),
            admin: false,
        }
    }

    /// Get the `sub` of the user to provision, aka the internal ID.
    #[must_use]
    pub fn sub(&self) -> &str {
        self.sub.as_str()
    }

    /// Get the handle of the user to provision.
    #[must_use]
    pub fn handle(&self) -> &str {
        self.handle.as_str()
    }

    /// Ask to set the displayname of the user.
    ///
    /// # Parameters
    ///
    /// * `displayname` - The displayname to set.
    #[must_use]
    pub fn set_displayname(mut self, displayname: String) -> Self {
        self.displayname = FieldUpdate::Assign(displayname);
        self
    }

    /// Ask to unset the displayname of the user.
    #[must_use]
    pub fn unset_displayname(mut self) -> Self {
        self.displayname = FieldUpdate::Clear;
        self
    }

    /// Ask to set the avatar URL of the user.
    ///
    /// # Parameters
    ///
    /// * `avatar_url` - The avatar URL to set.
    #[must_use]
    pub fn set_avatar_url(mut self, avatar_url: String) -> Self {
        self.avatar_url = FieldUpdate::Assign(avatar_url);
        self
    }

    /// Ask to set the emails of the user.
    ///
    /// # Parameters
    ///
    /// * `emails` - The list of emails to set.
    #[must_use]
    pub fn set_emails(mut self, emails: Vec<String>) -> Self {
        self.emails = FieldUpdate::Assign(emails);
        self
    }

    /// Mark the user as an administrator in the downstream principal system.
    #[must_use]
    pub fn set_admin(mut self) -> Self {
        self.admin = true;
        self
    }

    /// Whether the user should be an administrator in the downstream principal
    /// system.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.admin
    }
}

/// One exact account-status publication delivery to a configured Station.
#[derive(Debug, Clone)]
pub struct PrincipalAccountStatusPublicationRequest {
    destination_name: String,
    idempotency_key: String,
    body_digest: arkret_wire::Hash,
    body: arkret_models_collaboration::account_lifecycle::AccountStatusPublicationRequestBody,
}

#[derive(Debug, Clone)]
pub struct PrincipalErasureReceiptRequest {
    destination_name: String,
    triggering_status_record_id: arkret_wire::AccountStatusRecordId,
    account_id: String,
    principal_id: arkret_wire::DidCoreId,
}

impl PrincipalErasureReceiptRequest {
    #[must_use]
    pub fn new(
        destination_name: String,
        triggering_status_record_id: arkret_wire::AccountStatusRecordId,
        account_id: String,
        principal_id: arkret_wire::DidCoreId,
    ) -> Self {
        Self {
            destination_name,
            triggering_status_record_id,
            account_id,
            principal_id,
        }
    }

    #[must_use]
    pub fn destination_name(&self) -> &str {
        &self.destination_name
    }

    #[must_use]
    pub fn triggering_status_record_id(&self) -> &arkret_wire::AccountStatusRecordId {
        &self.triggering_status_record_id
    }

    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    #[must_use]
    pub fn principal_id(&self) -> &arkret_wire::DidCoreId {
        &self.principal_id
    }
}

impl PrincipalAccountStatusPublicationRequest {
    /// Build a destination-scoped delivery request.
    #[must_use]
    pub fn new(
        destination_name: String,
        idempotency_key: String,
        body_digest: arkret_wire::Hash,
        body: arkret_models_collaboration::account_lifecycle::AccountStatusPublicationRequestBody,
    ) -> Self {
        Self {
            destination_name,
            idempotency_key,
            body_digest,
            body,
        }
    }

    #[must_use]
    pub fn destination_name(&self) -> &str {
        &self.destination_name
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    #[must_use]
    pub fn body_digest(&self) -> &arkret_wire::Hash {
        &self.body_digest
    }

    #[must_use]
    pub fn body(
        &self,
    ) -> &arkret_models_collaboration::account_lifecycle::AccountStatusPublicationRequestBody {
        &self.body
    }
}

/// Request to deliver a controller-approved Agent key authorization to the
/// configured Station.
#[derive(Debug, Clone)]
pub struct PrincipalAgentKeyPairCommitRequest {
    idempotency_key: String,
    request_digest: String,
    station_name: String,
    body: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody,
}

impl PrincipalAgentKeyPairCommitRequest {
    #[must_use]
    pub fn new(
        idempotency_key: String,
        request_digest: String,
        station_name: String,
        body: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody,
    ) -> Self {
        Self {
            idempotency_key,
            request_digest,
            station_name,
            body,
        }
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    #[must_use]
    pub fn station_name(&self) -> &str {
        &self.station_name
    }

    #[must_use]
    pub fn body(&self) -> &arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody {
        &self.body
    }

    #[must_use]
    pub fn authorized_event_id(&self) -> &str {
        self.body.authorize_event.event.event_id.as_str()
    }
}

/// Trait defining account and device synchronization hooks for a downstream
/// Arkret principal system.
///
/// This trait keeps account-lifecycle call sites testable while
/// Arkret/Soland integrations use session grants and downstream discovery.
#[async_trait::async_trait]
pub trait ConnectorAdmin: Send + Sync {
    /// Get the principal system authority used for generated account
    /// identifiers.
    fn account_id(&self) -> &str;

    /// Resolve the configured destination name and exact service audience
    /// used to select a durable account/PCR binding.
    fn account_status_destination(
        &self,
    ) -> Result<(String, arkret_wire::DidCoreId), anyhow::Error> {
        Err(anyhow::anyhow!(
            "account-status destination is not implemented by this principal connector"
        ))
    }

    /// Get the downstream principal account address for the given handle.
    ///
    /// # Parameters
    ///
    /// * `handle` - The local account handle.
    fn principal_address(&self, handle: &str) -> String {
        format!("{handle}@{}", self.account_id())
    }

    /// Verify a bearer token coming from a downstream principal service.
    ///
    /// Returns `true` if the token is valid, `false` otherwise.
    ///
    /// # Parameters
    ///
    /// * `token` - The token to verify.
    ///
    /// # Errors
    ///
    /// Returns an error if the token failed to verify.
    async fn verify_token(&self, token: &str) -> Result<bool, anyhow::Error>;

    /// Query the state of a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `handle` - The handle of the user to query.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the user
    /// does not exist.
    async fn query_user(&self, handle: &str) -> Result<ConnectorAccountProfile, anyhow::Error>;

    /// Provision a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `request` - a [`ConnectorProvisionRequest`] containing the details of the user to
    ///   provision.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the user
    /// could not be provisioned.
    async fn provision_user(
        &self,
        request: &ConnectorProvisionRequest,
    ) -> Result<bool, anyhow::Error>;

    /// Check whether a given handle is available in the downstream principal
    /// system.
    ///
    /// # Parameters
    ///
    /// * `handle` - The handle to check.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable.
    async fn is_handle_available(&self, handle: &str) -> Result<bool, anyhow::Error>;

    /// Create a device for a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `handle` - The handle of the user to create a device for.
    /// * `device_id` - The device ID to create.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the device
    /// could not be created.
    async fn upsert_device(
        &self,
        handle: &str,
        device_id: &str,
        initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error>;

    /// Update the display name of a device for a user in the downstream
    /// principal system.
    ///
    /// # Parameters
    ///
    /// * `handle` - The handle of the user to update a device for.
    /// * `device_id` - The device ID to update.
    /// * `display_name` - The new display name to set
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the device
    /// could not be updated.
    async fn update_device_display_name(
        &self,
        handle: &str,
        device_id: &str,
        display_name: &str,
    ) -> Result<(), anyhow::Error>;

    /// Delete a device for a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `handle` - The handle of the user to delete a device for.
    /// * `device_id` - The device ID to delete.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the device
    /// could not be deleted.
    async fn delete_device(&self, handle: &str, device_id: &str) -> Result<(), anyhow::Error>;

    /// Sync the list of devices of a user with the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `handle` - The handle of the user to sync the devices for.
    /// * `devices` - The list of devices to sync.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the devices
    /// could not be synced.
    async fn sync_devices(
        &self,
        handle: &str,
        devices: HashSet<String>,
    ) -> Result<(), anyhow::Error>;

    /// Submit a collaboration capability grant/revoke fan-out payload to the
    /// downstream principal system.
    ///
    /// Submit an exact authority-signed account-status publication.
    async fn submit_account_status_publication(
        &self,
        _request: &PrincipalAccountStatusPublicationRequest,
    ) -> Result<
        arkret_models_collaboration::account_lifecycle::AccountStatusPublicationOutcome,
        anyhow::Error,
    > {
        Err(anyhow::anyhow!(
            "account-status publication is not implemented by this principal connector"
        ))
    }

    /// Fetch and validate the terminal physical-erasure receipt created by an
    /// accepted erasure_pending status record. `None` means execution is still
    /// pending and must be retried; it never means completed.
    async fn erasure_receipt(
        &self,
        _request: &PrincipalErasureReceiptRequest,
    ) -> Result<
        Option<arkret_models_collaboration::governance::erasure::ErasureReceiptPackage>,
        anyhow::Error,
    > {
        Err(anyhow::anyhow!(
            "erasure receipt lookup is not implemented by this principal connector"
        ))
    }

    /// Deliver a controller-approved Agent key authorization to the
    /// downstream principal system.
    async fn commit_agent_key_pair(
        &self,
        _request: &PrincipalAgentKeyPairCommitRequest,
    ) -> Result<(), anyhow::Error> {
        Err(anyhow::anyhow!(
            "Agent key-pair commit is not implemented by this principal connector"
        ))
    }

    /// Delete a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `handle` - The handle of the user to delete.
    /// * `erase` - Whether to ask the downstream system to erase the user's data.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the user
    /// could not be deleted.
    async fn delete_user(&self, handle: &str, erase: bool) -> Result<(), anyhow::Error>;

    /// Set the displayname of a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `handle` - The handle of the user to set the displayname for.
    /// * `displayname` - The displayname to set.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the
    /// displayname could not be set.
    async fn set_displayname(&self, handle: &str, displayname: &str) -> Result<(), anyhow::Error>;

    /// Unset the displayname of a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `handle` - The handle of the user to unset the displayname for.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the
    /// displayname could not be unset.
    async fn unset_displayname(&self, handle: &str) -> Result<(), anyhow::Error>;
}

/// Helper trait: obtain a reference to the inner `ConnectorAdmin`
/// from a wrapper type. Used to de-duplicate the two blanket impls below.
trait AsAdmin {
    type Target: ConnectorAdmin + ?Sized;
    fn as_admin(&self) -> &Self::Target;
}

impl<T: ConnectorAdmin + ?Sized> AsAdmin for &T {
    type Target = T;
    fn as_admin(&self) -> &T {
        self
    }
}

impl<T: ConnectorAdmin + ?Sized> AsAdmin for Arc<T> {
    type Target = T;
    fn as_admin(&self) -> &T {
        self.as_ref()
    }
}

/// Blanket implementation: anything that can produce a `&dyn
/// ConnectorAdmin` via [`AsAdmin`] is itself a valid admin handle.
#[async_trait::async_trait]
impl<W> ConnectorAdmin for W
where
    W: AsAdmin + Send + Sync,
    W::Target: ConnectorAdmin,
{
    fn account_id(&self) -> &str {
        self.as_admin().account_id()
    }

    async fn verify_token(&self, token: &str) -> Result<bool, anyhow::Error> {
        self.as_admin().verify_token(token).await
    }

    async fn query_user(&self, handle: &str) -> Result<ConnectorAccountProfile, anyhow::Error> {
        self.as_admin().query_user(handle).await
    }

    async fn provision_user(
        &self,
        request: &ConnectorProvisionRequest,
    ) -> Result<bool, anyhow::Error> {
        self.as_admin().provision_user(request).await
    }

    async fn is_handle_available(&self, handle: &str) -> Result<bool, anyhow::Error> {
        self.as_admin().is_handle_available(handle).await
    }

    async fn upsert_device(
        &self,
        handle: &str,
        device_id: &str,
        initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        self.as_admin()
            .upsert_device(handle, device_id, initial_display_name)
            .await
    }

    async fn update_device_display_name(
        &self,
        handle: &str,
        device_id: &str,
        display_name: &str,
    ) -> Result<(), anyhow::Error> {
        self.as_admin()
            .update_device_display_name(handle, device_id, display_name)
            .await
    }

    async fn delete_device(&self, handle: &str, device_id: &str) -> Result<(), anyhow::Error> {
        self.as_admin().delete_device(handle, device_id).await
    }

    async fn sync_devices(
        &self,
        handle: &str,
        devices: HashSet<String>,
    ) -> Result<(), anyhow::Error> {
        self.as_admin().sync_devices(handle, devices).await
    }

    async fn submit_account_status_publication(
        &self,
        request: &PrincipalAccountStatusPublicationRequest,
    ) -> Result<
        arkret_models_collaboration::account_lifecycle::AccountStatusPublicationOutcome,
        anyhow::Error,
    > {
        self.as_admin()
            .submit_account_status_publication(request)
            .await
    }

    async fn erasure_receipt(
        &self,
        request: &PrincipalErasureReceiptRequest,
    ) -> Result<
        Option<arkret_models_collaboration::governance::erasure::ErasureReceiptPackage>,
        anyhow::Error,
    > {
        self.as_admin().erasure_receipt(request).await
    }

    async fn commit_agent_key_pair(
        &self,
        request: &PrincipalAgentKeyPairCommitRequest,
    ) -> Result<(), anyhow::Error> {
        self.as_admin().commit_agent_key_pair(request).await
    }

    async fn delete_user(&self, handle: &str, erase: bool) -> Result<(), anyhow::Error> {
        self.as_admin().delete_user(handle, erase).await
    }

    async fn set_displayname(&self, handle: &str, displayname: &str) -> Result<(), anyhow::Error> {
        self.as_admin().set_displayname(handle, displayname).await
    }

    async fn unset_displayname(&self, handle: &str) -> Result<(), anyhow::Error> {
        self.as_admin().unset_displayname(handle).await
    }
}

/// A connector provider represents an external system that coauth can
/// provision users into, query state from, and synchronize with.
///
/// [`ConnectorAdmin`] is the primary implementation of this trait
/// for Arkret/Soland-facing principal connectors.
pub trait ConnectorProvider: ConnectorAdmin {
    /// A human-readable name for this connector (e.g. "soland").
    fn provider_name(&self) -> &str;
}
