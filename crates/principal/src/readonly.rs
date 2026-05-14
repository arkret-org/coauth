use std::collections::HashSet;

use crate::{
    ConnectorCapabilities, ConnectorProvider, PrincipalAccountProfile, PrincipalProvisionRequest,
    PrincipalServerAdmin,
};

#[derive(Clone, Copy)]
enum BlockedPrincipalWrite {
    ProvisionUser,
    UpsertDevice,
    UpdateDeviceDisplayName,
    DeleteDevice,
    SyncDevices,
    DeleteUser,
    ReactivateUser,
    SetDisplayname,
    UnsetDisplayname,
}

impl BlockedPrincipalWrite {
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
        }
    }
}

fn read_only_error(operation: BlockedPrincipalWrite) -> anyhow::Error {
    anyhow::anyhow!(
        "principal connector is configured as read-only and cannot {}",
        operation.summary()
    )
}

fn deny_write<T>(operation: BlockedPrincipalWrite) -> Result<T, anyhow::Error> {
    Err(read_only_error(operation))
}

/// Wraps a principal connector and forwards only read operations.
pub struct ReadOnlyPrincipalServerAdmin<C> {
    source: C,
}

impl<C> ReadOnlyPrincipalServerAdmin<C> {
    #[must_use]
    pub fn new(source: C) -> Self {
        Self { source }
    }
}

#[async_trait::async_trait]
impl<C: PrincipalServerAdmin> PrincipalServerAdmin for ReadOnlyPrincipalServerAdmin<C> {
    fn principal_authority(&self) -> &str {
        self.source.principal_authority()
    }

    async fn verify_token(&self, token: &str) -> Result<bool, anyhow::Error> {
        self.source.verify_token(token).await
    }

    async fn query_user(&self, handle: &str) -> Result<PrincipalAccountProfile, anyhow::Error> {
        self.source.query_user(handle).await
    }

    async fn provision_user(
        &self,
        _request: &PrincipalProvisionRequest,
    ) -> Result<bool, anyhow::Error> {
        deny_write(BlockedPrincipalWrite::ProvisionUser)
    }

    async fn is_handle_available(&self, handle: &str) -> Result<bool, anyhow::Error> {
        self.source.is_handle_available(handle).await
    }

    async fn upsert_device(
        &self,
        _handle: &str,
        _device_id: &str,
        _initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        deny_write(BlockedPrincipalWrite::UpsertDevice)
    }

    async fn update_device_display_name(
        &self,
        _handle: &str,
        _device_id: &str,
        _display_name: &str,
    ) -> Result<(), anyhow::Error> {
        deny_write(BlockedPrincipalWrite::UpdateDeviceDisplayName)
    }

    async fn delete_device(&self, _handle: &str, _device_id: &str) -> Result<(), anyhow::Error> {
        deny_write(BlockedPrincipalWrite::DeleteDevice)
    }

    async fn sync_devices(
        &self,
        _handle: &str,
        _devices: HashSet<String>,
    ) -> Result<(), anyhow::Error> {
        deny_write(BlockedPrincipalWrite::SyncDevices)
    }

    async fn delete_user(&self, _handle: &str, _erase: bool) -> Result<(), anyhow::Error> {
        deny_write(BlockedPrincipalWrite::DeleteUser)
    }

    async fn reactivate_user(&self, _handle: &str) -> Result<(), anyhow::Error> {
        deny_write(BlockedPrincipalWrite::ReactivateUser)
    }

    async fn set_displayname(
        &self,
        _handle: &str,
        _displayname: &str,
    ) -> Result<(), anyhow::Error> {
        deny_write(BlockedPrincipalWrite::SetDisplayname)
    }

    async fn unset_displayname(&self, _handle: &str) -> Result<(), anyhow::Error> {
        deny_write(BlockedPrincipalWrite::UnsetDisplayname)
    }
}

impl<C: ConnectorProvider> ConnectorProvider for ReadOnlyPrincipalServerAdmin<C> {
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
    use crate::mock::PrincipalServerAdmin as MockPrincipalServerAdmin;

    impl ConnectorProvider for MockPrincipalServerAdmin {
        fn provider_name(&self) -> &str {
            "mock-principal"
        }

        fn capabilities(&self) -> ConnectorCapabilities {
            ConnectorCapabilities {
                can_provision_users: true,
                can_delete_users: true,
                can_manage_devices: true,
                can_set_displayname: true,
            }
        }
    }

    fn assert_all_writes_disabled(capabilities: ConnectorCapabilities) {
        assert!(!capabilities.can_provision_users);
        assert!(!capabilities.can_delete_users);
        assert!(!capabilities.can_manage_devices);
        assert!(!capabilities.can_set_displayname);
    }

    #[tokio::test]
    async fn forwards_read_operations_to_source() {
        let source = MockPrincipalServerAdmin::new("example.org");
        source.reserve_handle("reserved").await;
        source
            .provision_user(
                &PrincipalProvisionRequest::new("alice", "sub-alice")
                    .set_displayname("Alice".to_owned()),
            )
            .await
            .unwrap();

        let connection = ReadOnlyPrincipalServerAdmin::new(source);

        assert!(
            connection
                .verify_token(MockPrincipalServerAdmin::VALID_BEARER_TOKEN)
                .await
                .unwrap()
        );
        assert!(!connection.is_handle_available("alice").await.unwrap());
        assert!(!connection.is_handle_available("reserved").await.unwrap());

        let user = connection.query_user("alice").await.unwrap();
        assert_eq!(user.displayname.as_deref(), Some("Alice"));
    }

    #[tokio::test]
    async fn blocks_mutations_and_reports_no_write_capabilities() {
        let connection =
            ReadOnlyPrincipalServerAdmin::new(MockPrincipalServerAdmin::new("example.org"));

        assert_eq!(connection.provider_name(), "mock-principal");
        assert_all_writes_disabled(connection.capabilities());

        let provision_error = connection
            .provision_user(&PrincipalProvisionRequest::new("bob", "sub-bob"))
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
