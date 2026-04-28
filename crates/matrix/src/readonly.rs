use std::collections::HashSet;

use crate::{
    ConnectorCapabilities, ConnectorProvider, HomeserverAdmin, MatrixUser, ProvisionRequest,
};

#[derive(Clone, Copy)]
enum BlockedMatrixWrite {
    ProvisionUser,
    UpsertDevice,
    UpdateDeviceDisplayName,
    DeleteDevice,
    SyncDevices,
    DeleteUser,
    ReactivateUser,
    SetDisplayname,
    UnsetDisplayname,
    AllowCrossSigningReset,
}

impl BlockedMatrixWrite {
    fn summary(self) -> &'static str {
        match self {
            Self::ProvisionUser => "provision users",
            Self::UpsertDevice => "create devices",
            Self::UpdateDeviceDisplayName => "rename devices",
            Self::DeleteDevice => "delete devices",
            Self::SyncDevices => "synchronize devices",
            Self::DeleteUser => "delete users",
            Self::ReactivateUser => "reactivate users",
            Self::SetDisplayname => "set display names",
            Self::UnsetDisplayname => "clear display names",
            Self::AllowCrossSigningReset => "allow cross-signing reset",
        }
    }
}

fn read_only_error(operation: BlockedMatrixWrite) -> anyhow::Error {
    anyhow::anyhow!(
        "matrix connector is configured as read-only and cannot {}",
        operation.summary()
    )
}

fn deny_write<T>(operation: BlockedMatrixWrite) -> Result<T, anyhow::Error> {
    Err(read_only_error(operation))
}

/// Wraps a homeserver connector and forwards only read operations.
pub struct ReadOnlyHomeserverAdmin<C> {
    source: C,
}

impl<C> ReadOnlyHomeserverAdmin<C> {
    #[must_use]
    pub fn new(source: C) -> Self {
        Self { source }
    }
}

#[async_trait::async_trait]
impl<C: HomeserverAdmin> HomeserverAdmin for ReadOnlyHomeserverAdmin<C> {
    fn homeserver(&self) -> &str {
        self.source.homeserver()
    }

    async fn verify_token(&self, token: &str) -> Result<bool, anyhow::Error> {
        self.source.verify_token(token).await
    }

    async fn query_user(&self, localpart: &str) -> Result<MatrixUser, anyhow::Error> {
        self.source.query_user(localpart).await
    }

    async fn provision_user(&self, _request: &ProvisionRequest) -> Result<bool, anyhow::Error> {
        deny_write(BlockedMatrixWrite::ProvisionUser)
    }

    async fn is_localpart_available(&self, localpart: &str) -> Result<bool, anyhow::Error> {
        self.source.is_localpart_available(localpart).await
    }

    async fn upsert_device(
        &self,
        _localpart: &str,
        _device_id: &str,
        _initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        deny_write(BlockedMatrixWrite::UpsertDevice)
    }

    async fn update_device_display_name(
        &self,
        _localpart: &str,
        _device_id: &str,
        _display_name: &str,
    ) -> Result<(), anyhow::Error> {
        deny_write(BlockedMatrixWrite::UpdateDeviceDisplayName)
    }

    async fn delete_device(&self, _localpart: &str, _device_id: &str) -> Result<(), anyhow::Error> {
        deny_write(BlockedMatrixWrite::DeleteDevice)
    }

    async fn sync_devices(
        &self,
        _localpart: &str,
        _devices: HashSet<String>,
    ) -> Result<(), anyhow::Error> {
        deny_write(BlockedMatrixWrite::SyncDevices)
    }

    async fn delete_user(&self, _localpart: &str, _erase: bool) -> Result<(), anyhow::Error> {
        deny_write(BlockedMatrixWrite::DeleteUser)
    }

    async fn reactivate_user(&self, _localpart: &str) -> Result<(), anyhow::Error> {
        deny_write(BlockedMatrixWrite::ReactivateUser)
    }

    async fn set_displayname(
        &self,
        _localpart: &str,
        _displayname: &str,
    ) -> Result<(), anyhow::Error> {
        deny_write(BlockedMatrixWrite::SetDisplayname)
    }

    async fn unset_displayname(&self, _localpart: &str) -> Result<(), anyhow::Error> {
        deny_write(BlockedMatrixWrite::UnsetDisplayname)
    }

    async fn allow_cross_signing_reset(&self, _localpart: &str) -> Result<(), anyhow::Error> {
        deny_write(BlockedMatrixWrite::AllowCrossSigningReset)
    }
}

impl<C: ConnectorProvider> ConnectorProvider for ReadOnlyHomeserverAdmin<C> {
    fn provider_name(&self) -> &str {
        self.source.provider_name()
    }

    fn capabilities(&self) -> ConnectorCapabilities {
        ConnectorCapabilities::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::HomeserverAdmin as MockHomeserverAdmin;

    impl ConnectorProvider for MockHomeserverAdmin {
        fn provider_name(&self) -> &str {
            "mock-homeserver"
        }

        fn capabilities(&self) -> ConnectorCapabilities {
            ConnectorCapabilities {
                can_provision_users: true,
                can_delete_users: true,
                can_manage_devices: true,
                can_set_displayname: true,
                can_cross_signing_reset: true,
            }
        }
    }

    fn assert_all_writes_disabled(capabilities: ConnectorCapabilities) {
        assert!(!capabilities.can_provision_users);
        assert!(!capabilities.can_delete_users);
        assert!(!capabilities.can_manage_devices);
        assert!(!capabilities.can_set_displayname);
        assert!(!capabilities.can_cross_signing_reset);
    }

    #[tokio::test]
    async fn forwards_read_operations_to_source() {
        let source = MockHomeserverAdmin::new("example.org");
        source.reserve_localpart("reserved").await;
        source
            .provision_user(
                &ProvisionRequest::new("alice", "sub-alice").set_displayname("Alice".to_owned()),
            )
            .await
            .unwrap();

        let connection = ReadOnlyHomeserverAdmin::new(source);

        assert!(
            connection
                .verify_token(MockHomeserverAdmin::VALID_BEARER_TOKEN)
                .await
                .unwrap()
        );
        assert!(!connection.is_localpart_available("alice").await.unwrap());
        assert!(!connection.is_localpart_available("reserved").await.unwrap());

        let user = connection.query_user("alice").await.unwrap();
        assert_eq!(user.displayname.as_deref(), Some("Alice"));
    }

    #[tokio::test]
    async fn blocks_mutations_and_reports_no_write_capabilities() {
        let connection = ReadOnlyHomeserverAdmin::new(MockHomeserverAdmin::new("example.org"));

        assert_eq!(connection.provider_name(), "mock-homeserver");
        assert_all_writes_disabled(connection.capabilities());

        let provision_error = connection
            .provision_user(&ProvisionRequest::new("bob", "sub-bob"))
            .await
            .unwrap_err();
        assert!(provision_error.to_string().contains("read-only"));
        assert!(provision_error.to_string().contains("provision users"));

        let rename_error = connection
            .update_device_display_name("bob", "DEVICE", "Phone")
            .await
            .unwrap_err();
        assert!(rename_error.to_string().contains("rename devices"));
    }
}
