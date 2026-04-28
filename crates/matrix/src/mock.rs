use std::collections::{HashMap, HashSet};

use anyhow::Context;
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{MatrixUser, ProvisionRequest};

/// Internal representation of a single user's profile and device state
/// within the mock homeserver.
struct UserRecord {
    subject_id: String,
    avatar_url: Option<String>,
    displayname: Option<String>,
    device_ids: HashSet<String>,
    email_addresses: Option<Vec<String>>,
    cross_signing_reset_permitted: bool,
    is_deactivated: bool,
}

/// Holds the full in-memory state backing a [`HomeserverAdmin`].
struct ServerState {
    accounts: HashMap<String, UserRecord>,
    blocked_localparts: HashSet<&'static str>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            blocked_localparts: HashSet::new(),
        }
    }

    /// Retrieve a mutable reference to a user, or fail with a clear message.
    fn account_mut(&mut self, mxid: &str) -> Result<&mut UserRecord, anyhow::Error> {
        self.accounts
            .get_mut(mxid)
            .with_context(|| format!("No account found for {mxid}"))
    }

    /// Retrieve a shared reference to a user, or fail with a clear message.
    fn account(&self, mxid: &str) -> Result<&UserRecord, anyhow::Error> {
        self.accounts
            .get(mxid)
            .with_context(|| format!("No account found for {mxid}"))
    }
}

/// A mock implementation of a [`HomeserverAdmin`], which never fails and
/// doesn't do anything.
pub struct HomeserverAdmin {
    homeserver: String,
    state: RwLock<ServerState>,
}

impl HomeserverAdmin {
    /// A valid bearer token that will be accepted by
    /// [`crate::HomeserverAdmin::verify_token`].
    pub const VALID_BEARER_TOKEN: &str = "mock_homeserver_bearer_token";

    /// Create a new mock connection.
    pub fn new<H>(homeserver: H) -> Self
    where
        H: Into<String>,
    {
        Self {
            homeserver: homeserver.into(),
            state: RwLock::new(ServerState::new()),
        }
    }

    pub async fn reserve_localpart(&self, localpart: &'static str) {
        self.state
            .write()
            .await
            .blocked_localparts
            .insert(localpart);
    }
}

#[async_trait]
impl crate::HomeserverAdmin for HomeserverAdmin {
    fn homeserver(&self) -> &str {
        self.homeserver.as_str()
    }

    async fn verify_token(&self, token: &str) -> Result<bool, anyhow::Error> {
        Ok(token == Self::VALID_BEARER_TOKEN)
    }

    async fn query_user(&self, localpart: &str) -> Result<MatrixUser, anyhow::Error> {
        let full_id = self.mxid(localpart);
        let guard = self.state.read().await;
        let record = guard.account(&full_id)?;
        Ok(MatrixUser {
            displayname: record.displayname.clone(),
            avatar_url: record.avatar_url.clone(),
            deactivated: record.is_deactivated,
        })
    }

    async fn provision_user(&self, request: &ProvisionRequest) -> Result<bool, anyhow::Error> {
        let full_id = self.mxid(request.localpart());
        let mut guard = self.state.write().await;

        let is_new_account = !guard.accounts.contains_key(&full_id);

        let record = guard.accounts.entry(full_id).or_insert_with(|| UserRecord {
            subject_id: request.sub().to_owned(),
            avatar_url: None,
            displayname: None,
            device_ids: HashSet::new(),
            email_addresses: None,
            cross_signing_reset_permitted: false,
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

    async fn is_localpart_available(&self, localpart: &str) -> Result<bool, anyhow::Error> {
        let guard = self.state.read().await;

        if guard.blocked_localparts.contains(localpart) {
            return Ok(false);
        }

        let full_id = self.mxid(localpart);
        Ok(!guard.accounts.contains_key(&full_id))
    }

    async fn upsert_device(
        &self,
        localpart: &str,
        device_id: &str,
        _initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let full_id = self.mxid(localpart);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.device_ids.insert(device_id.to_owned());
        Ok(())
    }

    async fn update_device_display_name(
        &self,
        localpart: &str,
        device_id: &str,
        _display_name: &str,
    ) -> Result<(), anyhow::Error> {
        let full_id = self.mxid(localpart);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        anyhow::ensure!(record.device_ids.contains(device_id), "Device not found");
        Ok(())
    }

    async fn delete_device(&self, localpart: &str, device_id: &str) -> Result<(), anyhow::Error> {
        let full_id = self.mxid(localpart);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.device_ids.remove(device_id);
        Ok(())
    }

    async fn sync_devices(
        &self,
        localpart: &str,
        devices: HashSet<String>,
    ) -> Result<(), anyhow::Error> {
        let full_id = self.mxid(localpart);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.device_ids = devices;
        Ok(())
    }

    async fn delete_user(&self, localpart: &str, erase: bool) -> Result<(), anyhow::Error> {
        let full_id = self.mxid(localpart);
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

    async fn reactivate_user(&self, localpart: &str) -> Result<(), anyhow::Error> {
        let full_id = self.mxid(localpart);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.is_deactivated = false;
        Ok(())
    }

    async fn set_displayname(
        &self,
        localpart: &str,
        displayname: &str,
    ) -> Result<(), anyhow::Error> {
        let full_id = self.mxid(localpart);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.displayname = Some(displayname.to_owned());
        Ok(())
    }

    async fn unset_displayname(&self, localpart: &str) -> Result<(), anyhow::Error> {
        let full_id = self.mxid(localpart);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.displayname = None;
        Ok(())
    }

    async fn allow_cross_signing_reset(&self, localpart: &str) -> Result<(), anyhow::Error> {
        let full_id = self.mxid(localpart);
        let mut guard = self.state.write().await;
        let record = guard.account_mut(&full_id)?;
        record.cross_signing_reset_permitted = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HomeserverAdmin as _;

    #[tokio::test]
    async fn test_mock_admin() {
        let conn = HomeserverAdmin::new("example.org");

        let mxid = "@test:example.org";
        let device = "test";
        assert_eq!(conn.homeserver(), "example.org");
        assert_eq!(conn.mxid("test"), mxid);

        assert!(conn.query_user("test").await.is_err());
        assert!(conn.upsert_device("test", device, None).await.is_err());
        assert!(conn.delete_device("test", device).await.is_err());

        let request = ProvisionRequest::new("test", "test")
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
        assert!(!conn.is_localpart_available("test").await.unwrap());
        // But another user should be
        assert!(conn.is_localpart_available("alice").await.unwrap());

        // Reserve the localpart, it should not be available anymore
        conn.reserve_localpart("alice").await;
        assert!(!conn.is_localpart_available("alice").await.unwrap());
    }
}
