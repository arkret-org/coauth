use std::collections::{HashMap, HashSet};

use anyhow::Context;
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{PrincipalAccountProfile, PrincipalProvisionRequest};

/// Internal representation of a single user's profile and device state
/// within the mock principal connector.
struct UserRecord {
    subject_id: String,
    avatar_url: Option<String>,
    displayname: Option<String>,
    device_ids: HashSet<String>,
    email_addresses: Option<Vec<String>>,
    is_deactivated: bool,
}

/// Holds the full in-memory state backing a [`PrincipalServerAdmin`].
struct ServerState {
    accounts: HashMap<String, UserRecord>,
    blocked_handles: HashSet<&'static str>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            blocked_handles: HashSet::new(),
        }
    }

    /// Retrieve a mutable reference to a user, or fail with a clear message.
    fn account_mut(&mut self, principal_id: &str) -> Result<&mut UserRecord, anyhow::Error> {
        self.accounts
            .get_mut(principal_id)
            .with_context(|| format!("No account found for {principal_id}"))
    }

    /// Retrieve a shared reference to a user, or fail with a clear message.
    fn account(&self, principal_id: &str) -> Result<&UserRecord, anyhow::Error> {
        self.accounts
            .get(principal_id)
            .with_context(|| format!("No account found for {principal_id}"))
    }
}

/// A mock implementation of a [`PrincipalServerAdmin`], which never fails and
/// doesn't do anything.
pub struct PrincipalServerAdmin {
    server_name: String,
    state: RwLock<ServerState>,
}

impl PrincipalServerAdmin {
    /// A valid bearer token that will be accepted by
    /// [`crate::PrincipalServerAdmin::verify_token`].
    pub const VALID_BEARER_TOKEN: &str = "mock_principal_bearer_token";

    /// Create a new mock connection.
    pub fn new<H>(server_name: H) -> Self
    where
        H: Into<String>,
    {
        Self {
            server_name: server_name.into(),
            state: RwLock::new(ServerState::new()),
        }
    }

    pub async fn reserve_handle(&self, handle: &'static str) {
        self.state.write().await.blocked_handles.insert(handle);
    }
}

#[async_trait]
impl crate::PrincipalServerAdmin for PrincipalServerAdmin {
    fn principal_authority(&self) -> &str {
        self.server_name.as_str()
    }

    async fn verify_token(&self, token: &str) -> Result<bool, anyhow::Error> {
        Ok(token == Self::VALID_BEARER_TOKEN)
    }

    async fn query_user(&self, handle: &str) -> Result<PrincipalAccountProfile, anyhow::Error> {
        let full_id = self.principal_id(handle);
        let guard = self.state.read().await;
        let record = guard.account(&full_id)?;
        Ok(PrincipalAccountProfile {
            displayname: record.displayname.clone(),
            avatar_url: record.avatar_url.clone(),
            deactivated: record.is_deactivated,
        })
    }

    async fn provision_user(
        &self,
        request: &PrincipalProvisionRequest,
    ) -> Result<bool, anyhow::Error> {
        let full_id = self.principal_id(request.handle());
        let mut guard = self.state.write().await;

        let is_new_account = !guard.accounts.contains_key(&full_id);

        let record = guard.accounts.entry(full_id).or_insert_with(|| UserRecord {
            subject_id: request.sub().to_owned(),
            avatar_url: None,
            displayname: None,
            device_ids: HashSet::new(),
            email_addresses: None,
            is_deactivated: false,
        });

        anyhow::ensure!(
            record.subject_id == request.sub(),
            "User already provisioned with different sub"
        );

        request.on_emails(|maybe_emails| {
            record.email_addresses = maybe_emails.map(ToOwned::to_owned);
        });

        request.on_displayname(|maybe_name| {
            record.displayname = maybe_name.map(ToOwned::to_owned);
        });

        request.on_avatar_url(|maybe_url| {
            record.avatar_url = maybe_url.map(ToOwned::to_owned);
        });

        Ok(is_new_account)
    }

    async fn is_handle_available(&self, handle: &str) -> Result<bool, anyhow::Error> {
        let guard = self.state.read().await;

        if guard.blocked_handles.contains(handle) {
            return Ok(false);
        }

        let full_id = self.principal_id(handle);
        Ok(!guard.accounts.contains_key(&full_id))
    }

    async fn upsert_device(
        &self,
        handle: &str,
        device_id: &str,
        _initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let full_id = self.principal_id(handle);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.device_ids.insert(device_id.to_owned());
        Ok(())
    }

    async fn update_device_display_name(
        &self,
        handle: &str,
        device_id: &str,
        _display_name: &str,
    ) -> Result<(), anyhow::Error> {
        let full_id = self.principal_id(handle);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        anyhow::ensure!(record.device_ids.contains(device_id), "Device not found");
        Ok(())
    }

    async fn delete_device(&self, handle: &str, device_id: &str) -> Result<(), anyhow::Error> {
        let full_id = self.principal_id(handle);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.device_ids.remove(device_id);
        Ok(())
    }

    async fn sync_devices(
        &self,
        handle: &str,
        devices: HashSet<String>,
    ) -> Result<(), anyhow::Error> {
        let full_id = self.principal_id(handle);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.device_ids = devices;
        Ok(())
    }

    async fn delete_user(&self, handle: &str, erase: bool) -> Result<(), anyhow::Error> {
        let full_id = self.principal_id(handle);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;

        record.device_ids.clear();
        record.email_addresses = None;
        record.is_deactivated = true;

        if erase {
            record.avatar_url = None;
            record.displayname = None;
        }

        Ok(())
    }

    async fn reactivate_user(&self, handle: &str) -> Result<(), anyhow::Error> {
        let full_id = self.principal_id(handle);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.is_deactivated = false;
        Ok(())
    }

    async fn set_displayname(&self, handle: &str, displayname: &str) -> Result<(), anyhow::Error> {
        let full_id = self.principal_id(handle);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.displayname = Some(displayname.to_owned());
        Ok(())
    }

    async fn unset_displayname(&self, handle: &str) -> Result<(), anyhow::Error> {
        let full_id = self.principal_id(handle);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.displayname = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrincipalServerAdmin as _;

    #[tokio::test]
    async fn test_mock_admin() {
        let conn = PrincipalServerAdmin::new("example.org");

        let principal_id = "test@example.org";
        let device = "test";
        assert_eq!(conn.principal_authority(), "example.org");
        assert_eq!(conn.principal_id("test"), principal_id);

        assert!(conn.query_user("test").await.is_err());
        assert!(conn.upsert_device("test", device, None).await.is_err());
        assert!(conn.delete_device("test", device).await.is_err());

        let request = PrincipalProvisionRequest::new("test", "test")
            .set_displayname("Test User".into())
            .set_avatar_url("mxc://example.org/1234567890".into())
            .set_emails(vec!["test@example.org".to_owned()]);

        let inserted = conn.provision_user(&request).await.unwrap();
        assert!(inserted);

        let user = conn.query_user("test").await.unwrap();
        assert_eq!(user.displayname, Some("Test User".into()));
        assert_eq!(user.avatar_url, Some("mxc://example.org/1234567890".into()));

        // Set the displayname again
        assert!(conn.set_displayname("test", "John").await.is_ok());

        let user = conn.query_user("test").await.unwrap();
        assert_eq!(user.displayname, Some("John".into()));

        // Unset the displayname
        assert!(conn.unset_displayname("test").await.is_ok());

        let user = conn.query_user("test").await.unwrap();
        assert_eq!(user.displayname, None);

        // Deleting a non-existent device should not fail
        assert!(conn.delete_device("test", device).await.is_ok());

        // Create the device
        assert!(conn.upsert_device("test", device, None).await.is_ok());
        // Create the same device again (idempotent)
        assert!(conn.upsert_device("test", device, None).await.is_ok());

        // Delete the device
        assert!(conn.delete_device("test", device).await.is_ok());

        // The user we just created should be not available
        assert!(!conn.is_handle_available("test").await.unwrap());
        // But another user should be
        assert!(conn.is_handle_available("alice").await.unwrap());

        // Reserve the handle, it should not be available anymore
        conn.reserve_handle("alice").await;
        assert!(!conn.is_handle_available("alice").await.unwrap());
    }
}
