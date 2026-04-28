mod mock;
mod readonly;
pub mod registry;

use std::{collections::HashSet, sync::Arc};

use ruma_common::UserId;

pub use self::{
    mock::HomeserverAdmin as MockHomeserverAdmin, readonly::ReadOnlyHomeserverAdmin,
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
    /// Whether the connector supports cross-signing reset.
    pub can_cross_signing_reset: bool,
}

#[derive(Debug)]
pub struct MatrixUser {
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

pub struct ProvisionRequest {
    localpart: String,
    sub: String,
    displayname: FieldUpdate<String>,
    avatar_url: FieldUpdate<String>,
    emails: FieldUpdate<Vec<String>>,
    admin: bool,
}

impl ProvisionRequest {
    /// Create a new [`ProvisionRequest`].
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user to provision.
    /// * `sub` - The `sub` of the user, aka the internal ID.
    #[must_use]
    pub fn new(localpart: impl Into<String>, sub: impl Into<String>) -> Self {
        Self {
            localpart: localpart.into(),
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

    /// Get the localpart of the user to provision.
    #[must_use]
    pub fn localpart(&self) -> &str {
        self.localpart.as_str()
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

    /// Mark the user as a homeserver admin.
    #[must_use]
    pub fn set_admin(mut self) -> Self {
        self.admin = true;
        self
    }

    /// Whether the user should be a homeserver admin.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.admin
    }
}

/// Trait defining operations against a Matrix homeserver.
///
/// Implementations can target real homeservers (e.g. via the admin API) or
/// in-memory fakes for testing.
#[async_trait::async_trait]
pub trait HomeserverAdmin: Send + Sync {
    /// Get the homeserver URL.
    fn homeserver(&self) -> &str;

    /// Get the Matrix ID of the user with the given localpart.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user.
    fn mxid(&self, localpart: &str) -> String {
        format!("@{}:{}", localpart, self.homeserver())
    }

    /// Get the localpart of a Matrix ID if it has the right server name
    ///
    /// Returns [`None`] if the input isn't a valid MXID, or if the server name
    /// doesn't match
    ///
    /// # Parameters
    ///
    /// * `mxid` - The MXID of the user
    fn localpart<'a>(&self, mxid: &'a str) -> Option<&'a str> {
        let parsed = <&UserId>::try_from(mxid).ok()?;
        if parsed.server_name() != self.homeserver() {
            return None;
        }
        Some(parsed.localpart())
    }

    /// Verify a bearer token coming from the homeserver for homeserver to
    /// Pasion interactions
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

    /// Query the state of a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user to query.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the user does not
    /// exist.
    async fn query_user(&self, localpart: &str) -> Result<MatrixUser, anyhow::Error>;

    /// Provision a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `request` - a [`ProvisionRequest`] containing the details of the user
    ///   to provision.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the user could not
    /// be provisioned.
    async fn provision_user(&self, request: &ProvisionRequest) -> Result<bool, anyhow::Error>;

    /// Check whether a given username is available on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart to check.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable.
    async fn is_localpart_available(&self, localpart: &str) -> Result<bool, anyhow::Error>;

    /// Create a device for a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user to create a device for.
    /// * `device_id` - The device ID to create.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the device could
    /// not be created.
    async fn upsert_device(
        &self,
        localpart: &str,
        device_id: &str,
        initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error>;

    /// Update the display name of a device for a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user to update a device for.
    /// * `device_id` - The device ID to update.
    /// * `display_name` - The new display name to set
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the device could
    /// not be updated.
    async fn update_device_display_name(
        &self,
        localpart: &str,
        device_id: &str,
        display_name: &str,
    ) -> Result<(), anyhow::Error>;

    /// Delete a device for a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user to delete a device for.
    /// * `device_id` - The device ID to delete.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the device could
    /// not be deleted.
    async fn delete_device(&self, localpart: &str, device_id: &str) -> Result<(), anyhow::Error>;

    /// Sync the list of devices of a user with the homeserver.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user to sync the devices for.
    /// * `devices` - The list of devices to sync.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the devices could
    /// not be synced.
    async fn sync_devices(
        &self,
        localpart: &str,
        devices: HashSet<String>,
    ) -> Result<(), anyhow::Error>;

    /// Delete a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user to delete.
    /// * `erase` - Whether to ask the homeserver to erase the user's data.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the user could not
    /// be deleted.
    async fn delete_user(&self, localpart: &str, erase: bool) -> Result<(), anyhow::Error>;

    /// Reactivate a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user to reactivate.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the user could not
    /// be reactivated.
    async fn reactivate_user(&self, localpart: &str) -> Result<(), anyhow::Error>;

    /// Set the displayname of a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user to set the displayname for.
    /// * `displayname` - The displayname to set.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the displayname
    /// could not be set.
    async fn set_displayname(
        &self,
        localpart: &str,
        displayname: &str,
    ) -> Result<(), anyhow::Error>;

    /// Unset the displayname of a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user to unset the displayname for.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the displayname
    /// could not be unset.
    async fn unset_displayname(&self, localpart: &str) -> Result<(), anyhow::Error>;

    /// Temporarily allow a user to reset their cross-signing keys.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user to allow cross-signing key
    ///   reset
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the cross-signing
    /// reset could not be allowed.
    async fn allow_cross_signing_reset(&self, localpart: &str) -> Result<(), anyhow::Error>;
}

/// Helper trait: obtain a reference to the inner `HomeserverAdmin`
/// from a wrapper type. Used to de-duplicate the two blanket impls below.
trait AsAdmin {
    type Target: HomeserverAdmin + ?Sized;
    fn as_admin(&self) -> &Self::Target;
}

impl<T: HomeserverAdmin + ?Sized> AsAdmin for &T {
    type Target = T;
    fn as_admin(&self) -> &T {
        *self
    }
}

impl<T: HomeserverAdmin + ?Sized> AsAdmin for Arc<T> {
    type Target = T;
    fn as_admin(&self) -> &T {
        self.as_ref()
    }
}

/// Blanket implementation: anything that can produce a `&dyn HomeserverAdmin`
/// via [`AsAdmin`] is itself a valid admin handle.
#[async_trait::async_trait]
impl<W> HomeserverAdmin for W
where
    W: AsAdmin + Send + Sync,
    W::Target: HomeserverAdmin,
{
    fn homeserver(&self) -> &str {
        self.as_admin().homeserver()
    }

    async fn verify_token(&self, token: &str) -> Result<bool, anyhow::Error> {
        self.as_admin().verify_token(token).await
    }

    async fn query_user(&self, localpart: &str) -> Result<MatrixUser, anyhow::Error> {
        self.as_admin().query_user(localpart).await
    }

    async fn provision_user(&self, request: &ProvisionRequest) -> Result<bool, anyhow::Error> {
        self.as_admin().provision_user(request).await
    }

    async fn is_localpart_available(&self, localpart: &str) -> Result<bool, anyhow::Error> {
        self.as_admin().is_localpart_available(localpart).await
    }

    async fn upsert_device(
        &self,
        localpart: &str,
        device_id: &str,
        initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        self.as_admin()
            .upsert_device(localpart, device_id, initial_display_name)
            .await
    }

    async fn update_device_display_name(
        &self,
        localpart: &str,
        device_id: &str,
        display_name: &str,
    ) -> Result<(), anyhow::Error> {
        self.as_admin()
            .update_device_display_name(localpart, device_id, display_name)
            .await
    }

    async fn delete_device(&self, localpart: &str, device_id: &str) -> Result<(), anyhow::Error> {
        self.as_admin().delete_device(localpart, device_id).await
    }

    async fn sync_devices(
        &self,
        localpart: &str,
        devices: HashSet<String>,
    ) -> Result<(), anyhow::Error> {
        self.as_admin().sync_devices(localpart, devices).await
    }

    async fn delete_user(&self, localpart: &str, erase: bool) -> Result<(), anyhow::Error> {
        self.as_admin().delete_user(localpart, erase).await
    }

    async fn reactivate_user(&self, localpart: &str) -> Result<(), anyhow::Error> {
        self.as_admin().reactivate_user(localpart).await
    }

    async fn set_displayname(
        &self,
        localpart: &str,
        displayname: &str,
    ) -> Result<(), anyhow::Error> {
        self.as_admin()
            .set_displayname(localpart, displayname)
            .await
    }

    async fn unset_displayname(&self, localpart: &str) -> Result<(), anyhow::Error> {
        self.as_admin().unset_displayname(localpart).await
    }

    async fn allow_cross_signing_reset(&self, localpart: &str) -> Result<(), anyhow::Error> {
        self.as_admin().allow_cross_signing_reset(localpart).await
    }
}

/// A connector provider represents an external system that Pasion can
/// provision users into, query state from, and synchronize with.
///
/// [`HomeserverAdmin`] is the primary implementation of this trait
/// for Matrix homeserver backends like Palpo.
pub trait ConnectorProvider: HomeserverAdmin {
    /// A human-readable name for this connector (e.g. "Palpo", "Synapse").
    fn provider_name(&self) -> &str;

    /// Returns the set of capabilities this connector supports.
    fn capabilities(&self) -> ConnectorCapabilities {
        ConnectorCapabilities::default()
    }
}
