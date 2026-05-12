// Copyright (c) 2026 Contrix Authors. Licensed under the Apache License, Version 2.0; see LICENSE-APACHE for details.
// Originally developed for the legacy delegated-auth connector.

mod mock;
mod readonly;
pub mod registry;

use std::{collections::HashSet, sync::Arc};

pub use self::{
    mock::PrincipalServerAdmin as MockPrincipalServerAdmin, readonly::ReadOnlyPrincipalServerAdmin,
    registry::ConnectorRegistry,
};

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
pub struct PrincipalAccountProfile {
    pub displayname: Option<String>,
    pub avatar_url: Option<String>,
    pub deactivated: bool,
}

/// Represents an optional mutation for a user profile field during
/// provisioning. Each variant captures whether the caller wants to
/// leave the field alone, assign a value, or clear it.
#[derive(Debug)]
enum FieldUpdate<T> {
    Unchanged,
    Assign(T),
    Clear,
}

impl<T> Default for FieldUpdate<T> {
    fn default() -> Self {
        Self::Unchanged
    }
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

pub struct PrincipalProvisionRequest {
    username: String,
    sub: String,
    displayname: FieldUpdate<String>,
    avatar_url: FieldUpdate<String>,
    emails: FieldUpdate<Vec<String>>,
    admin: bool,
}

impl PrincipalProvisionRequest {
    /// Create a new [`PrincipalProvisionRequest`].
    ///
    /// # Parameters
    ///
    /// * `username` - The username of the user to provision.
    /// * `sub` - The `sub` of the user, aka the internal ID.
    #[must_use]
    pub fn new(username: impl Into<String>, sub: impl Into<String>) -> Self {
        Self {
            username: username.into(),
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

    /// Get the username of the user to provision.
    #[must_use]
    pub fn username(&self) -> &str {
        self.username.as_str()
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

/// Trait defining account and device synchronization hooks for a downstream
/// Contrix principal system.
///
/// This trait keeps account-lifecycle call sites testable while
/// Contrix/Soland integrations use session grants and Principal Server
/// discovery.
#[async_trait::async_trait]
pub trait PrincipalServerAdmin: Send + Sync {
    /// Get the principal system authority used for generated account
    /// identifiers.
    fn principal_authority(&self) -> &str;

    /// Get the downstream principal account ID for the given username.
    ///
    /// # Parameters
    ///
    /// * `username` - The local account username.
    fn principal_id(&self, username: &str) -> String {
        format!("{username}@{}", self.principal_authority())
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
    /// * `username` - The username of the user to query.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the user does not
    /// exist.
    async fn query_user(&self, username: &str) -> Result<PrincipalAccountProfile, anyhow::Error>;

    /// Provision a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `request` - a [`PrincipalProvisionRequest`] containing the details of the user
    ///   to provision.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the user could not
    /// be provisioned.
    async fn provision_user(
        &self,
        request: &PrincipalProvisionRequest,
    ) -> Result<bool, anyhow::Error>;

    /// Check whether a given username is available in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `username` - The username to check.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable.
    async fn is_username_available(&self, username: &str) -> Result<bool, anyhow::Error>;

    /// Create a device for a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `username` - The username of the user to create a device for.
    /// * `device_id` - The device ID to create.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the device could
    /// not be created.
    async fn upsert_device(
        &self,
        username: &str,
        device_id: &str,
        initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error>;

    /// Update the display name of a device for a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `username` - The username of the user to update a device for.
    /// * `device_id` - The device ID to update.
    /// * `display_name` - The new display name to set
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the device could
    /// not be updated.
    async fn update_device_display_name(
        &self,
        username: &str,
        device_id: &str,
        display_name: &str,
    ) -> Result<(), anyhow::Error>;

    /// Delete a device for a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `username` - The username of the user to delete a device for.
    /// * `device_id` - The device ID to delete.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the device could
    /// not be deleted.
    async fn delete_device(&self, username: &str, device_id: &str) -> Result<(), anyhow::Error>;

    /// Sync the list of devices of a user with the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `username` - The username of the user to sync the devices for.
    /// * `devices` - The list of devices to sync.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the devices could
    /// not be synced.
    async fn sync_devices(
        &self,
        username: &str,
        devices: HashSet<String>,
    ) -> Result<(), anyhow::Error>;

    /// Delete a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `username` - The username of the user to delete.
    /// * `erase` - Whether to ask the downstream system to erase the user's data.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the user could not
    /// be deleted.
    async fn delete_user(&self, username: &str, erase: bool) -> Result<(), anyhow::Error>;

    /// Reactivate a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `username` - The username of the user to reactivate.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the user could not
    /// be reactivated.
    async fn reactivate_user(&self, username: &str) -> Result<(), anyhow::Error>;

    /// Set the displayname of a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `username` - The username of the user to set the displayname for.
    /// * `displayname` - The displayname to set.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the displayname
    /// could not be set.
    async fn set_displayname(&self, username: &str, displayname: &str)
    -> Result<(), anyhow::Error>;

    /// Unset the displayname of a user in the downstream principal system.
    ///
    /// # Parameters
    ///
    /// * `username` - The username of the user to unset the displayname for.
    ///
    /// # Errors
    ///
    /// Returns an error if the downstream system is unreachable or the displayname
    /// could not be unset.
    async fn unset_displayname(&self, username: &str) -> Result<(), anyhow::Error>;
}

/// Helper trait: obtain a reference to the inner `PrincipalServerAdmin`
/// from a wrapper type. Used to de-duplicate the two blanket impls below.
trait AsAdmin {
    type Target: PrincipalServerAdmin + ?Sized;
    fn as_admin(&self) -> &Self::Target;
}

impl<T: PrincipalServerAdmin + ?Sized> AsAdmin for &T {
    type Target = T;
    fn as_admin(&self) -> &T {
        *self
    }
}

impl<T: PrincipalServerAdmin + ?Sized> AsAdmin for Arc<T> {
    type Target = T;
    fn as_admin(&self) -> &T {
        self.as_ref()
    }
}

/// Blanket implementation: anything that can produce a `&dyn PrincipalServerAdmin`
/// via [`AsAdmin`] is itself a valid admin handle.
#[async_trait::async_trait]
impl<W> PrincipalServerAdmin for W
where
    W: AsAdmin + Send + Sync,
    W::Target: PrincipalServerAdmin,
{
    fn principal_authority(&self) -> &str {
        self.as_admin().principal_authority()
    }

    async fn verify_token(&self, token: &str) -> Result<bool, anyhow::Error> {
        self.as_admin().verify_token(token).await
    }

    async fn query_user(&self, username: &str) -> Result<PrincipalAccountProfile, anyhow::Error> {
        self.as_admin().query_user(username).await
    }

    async fn provision_user(
        &self,
        request: &PrincipalProvisionRequest,
    ) -> Result<bool, anyhow::Error> {
        self.as_admin().provision_user(request).await
    }

    async fn is_username_available(&self, username: &str) -> Result<bool, anyhow::Error> {
        self.as_admin().is_username_available(username).await
    }

    async fn upsert_device(
        &self,
        username: &str,
        device_id: &str,
        initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        self.as_admin()
            .upsert_device(username, device_id, initial_display_name)
            .await
    }

    async fn update_device_display_name(
        &self,
        username: &str,
        device_id: &str,
        display_name: &str,
    ) -> Result<(), anyhow::Error> {
        self.as_admin()
            .update_device_display_name(username, device_id, display_name)
            .await
    }

    async fn delete_device(&self, username: &str, device_id: &str) -> Result<(), anyhow::Error> {
        self.as_admin().delete_device(username, device_id).await
    }

    async fn sync_devices(
        &self,
        username: &str,
        devices: HashSet<String>,
    ) -> Result<(), anyhow::Error> {
        self.as_admin().sync_devices(username, devices).await
    }

    async fn delete_user(&self, username: &str, erase: bool) -> Result<(), anyhow::Error> {
        self.as_admin().delete_user(username, erase).await
    }

    async fn reactivate_user(&self, username: &str) -> Result<(), anyhow::Error> {
        self.as_admin().reactivate_user(username).await
    }

    async fn set_displayname(
        &self,
        username: &str,
        displayname: &str,
    ) -> Result<(), anyhow::Error> {
        self.as_admin().set_displayname(username, displayname).await
    }

    async fn unset_displayname(&self, username: &str) -> Result<(), anyhow::Error> {
        self.as_admin().unset_displayname(username).await
    }
}

/// A connector provider represents an external system that coauth can
/// provision users into, query state from, and synchronize with.
///
/// [`PrincipalServerAdmin`] is the primary implementation of this trait
/// for Contrix/Soland-facing principal connectors.
pub trait ConnectorProvider: PrincipalServerAdmin {
    /// A human-readable name for this connector (e.g. "soland").
    fn provider_name(&self) -> &str;

    /// Returns the set of capabilities this connector supports.
    fn capabilities(&self) -> ConnectorCapabilities {
        ConnectorCapabilities::default()
    }
}
