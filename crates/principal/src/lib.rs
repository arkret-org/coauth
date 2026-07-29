// Copyright (c) 2026 Arkret Authors.
//
// SPDX-License-Identifier: AGPL-3.0-only

pub mod registry;

use std::collections::HashSet;
use std::sync::Arc;

use soland_contracts::integration::capability_fanout::CapabilityFanoutBody;

pub use self::registry::ConnectorRegistry;

/// Describes what operations a connector provider supports.
#[derive(Debug, Clone, Default)]
pub struct ConnectorCapabilities {
    /// Whether the connector can provision new users.
    pub can_provision_users: bool,
    /// Whether the connector can delete/deactivate users.
    pub can_delete_users: bool,
    /// Whether the connector can manage devices.
    pub can_manage_devices: bool,
    /// Whether the connector can set display names.
    pub can_set_displayname: bool,
}

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

impl<T> FieldUpdate<T> {
    /// Invoke `handler` when the field should be mutated (assigned or cleared).
    fn apply<F>(&self, handler: F)
    where
        F: FnOnce(Option<&T>),
    {
        match self {
            Self::Assign(val) => handler(Some(val)),
            Self::Clear => handler(None),
            Self::Unchanged => {}
        }
    }
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

    /// Call the given callback if the displayname should be set or unset.
    ///
    /// # Parameters
    ///
    /// * `callback` - The callback to call.
    pub fn on_displayname<F>(&self, callback: F) -> &Self
    where
        F: FnOnce(Option<&str>),
    {
        self.displayname
            .apply(|opt| callback(opt.map(String::as_str)));
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

    /// Ask to unset the avatar URL of the user.
    #[must_use]
    pub fn unset_avatar_url(mut self) -> Self {
        self.avatar_url = FieldUpdate::Clear;
        self
    }

    /// Call the given callback if the avatar URL should be set or unset.
    ///
    /// # Parameters
    ///
    /// * `callback` - The callback to call.
    pub fn on_avatar_url<F>(&self, callback: F) -> &Self
    where
        F: FnOnce(Option<&str>),
    {
        self.avatar_url
            .apply(|opt| callback(opt.map(String::as_str)));
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

    /// Ask to unset the emails of the user.
    #[must_use]
    pub fn unset_emails(mut self) -> Self {
        self.emails = FieldUpdate::Clear;
        self
    }

    /// Call the given callback if the emails should be set or unset.
    ///
    /// # Parameters
    ///
    /// * `callback` - The callback to call.
    pub fn on_emails<F>(&self, callback: F) -> &Self
    where
        F: FnOnce(Option<&[String]>),
    {
        self.emails.apply(|opt| callback(opt.map(Vec::as_slice)));
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

/// Request to submit a collaboration capability grant/revoke fan-out payload to
/// the configured principal system.
#[derive(Debug, Clone)]
pub struct PrincipalCapabilityFanoutRequest {
    idempotency_key: String,
    raw_payload_digest: String,
    body: CapabilityFanoutBody,
}

impl PrincipalCapabilityFanoutRequest {
    /// Create a new collaboration capability fan-out request.
    #[must_use]
    pub fn new(
        idempotency_key: String,
        raw_payload_digest: String,
        body: CapabilityFanoutBody,
    ) -> Self {
        Self {
            idempotency_key,
            raw_payload_digest,
            body,
        }
    }

    /// Fan-out operation wire value (`grant` / `revoke`).
    #[must_use]
    pub fn operation(&self) -> &str {
        self.body.operation.as_str()
    }

    /// Idempotency key for downstream delivery.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Standard capability grant id.
    #[must_use]
    pub fn capability_grant_id(&self) -> &str {
        self.body.capability_grant_id.as_str()
    }

    /// Standard capability grant/revoke event id.
    #[must_use]
    pub fn event_id(&self) -> &str {
        self.body.event_id.as_str()
    }

    /// Canonical digest of [`Self::body`].
    #[must_use]
    pub fn raw_payload_digest(&self) -> &str {
        &self.raw_payload_digest
    }

    /// Fan-out body to submit.
    #[must_use]
    pub fn body(&self) -> &CapabilityFanoutBody {
        &self.body
    }
}

/// Request to deliver a controller-approved Agent key authorization to the
/// configured Principal Server.
#[derive(Debug, Clone)]
pub struct PrincipalAgentKeyPairCommitRequest {
    idempotency_key: String,
    request_digest: String,
    principal_server_name: String,
    body: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody,
}

impl PrincipalAgentKeyPairCommitRequest {
    #[must_use]
    pub fn new(
        idempotency_key: String,
        request_digest: String,
        principal_server_name: String,
        body: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody,
    ) -> Self {
        Self {
            idempotency_key,
            request_digest,
            principal_server_name,
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
    pub fn principal_server_name(&self) -> &str {
        &self.principal_server_name
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
    fn principal_authority(&self) -> &str;

    /// Get the downstream principal account ID for the given handle.
    ///
    /// # Parameters
    ///
    /// * `handle` - The local account handle.
    fn principal_id(&self, handle: &str) -> String {
        format!("{handle}@{}", self.principal_authority())
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
    async fn submit_collaboration_capability_fanout(
        &self,
        _request: &PrincipalCapabilityFanoutRequest,
    ) -> Result<(), anyhow::Error> {
        Err(anyhow::anyhow!(
            "collaboration capability fanout is not implemented by this principal connector"
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

    /// Reactivate a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `handle` - The handle of the user to reactivate.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the user
    /// could not be reactivated.
    async fn reactivate_user(&self, handle: &str) -> Result<(), anyhow::Error>;

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
    fn principal_authority(&self) -> &str {
        self.as_admin().principal_authority()
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

    async fn submit_collaboration_capability_fanout(
        &self,
        request: &PrincipalCapabilityFanoutRequest,
    ) -> Result<(), anyhow::Error> {
        self.as_admin()
            .submit_collaboration_capability_fanout(request)
            .await
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

    async fn reactivate_user(&self, handle: &str) -> Result<(), anyhow::Error> {
        self.as_admin().reactivate_user(handle).await
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

    /// Returns the set of capabilities this connector supports.
    fn capabilities(&self) -> ConnectorCapabilities {
        ConnectorCapabilities::default()
    }
}
