//! Transaction-bound access to the issuer's original Station enrollment.

use coauth_data::storage::station_trust::StationTrustEnrollment;
use coauth_data::{
    BoxRepository, BoxRepositoryFactory, RepositoryAccess as _, RepositoryError, RepositoryFactory,
};

pub(super) struct PinnedIssuerRepositoryFactory {
    inner: BoxRepositoryFactory,
    binding: StationTrustEnrollment,
}

impl PinnedIssuerRepositoryFactory {
    pub(super) fn new(inner: BoxRepositoryFactory, binding: StationTrustEnrollment) -> Self {
        Self { inner, binding }
    }
}

#[async_trait::async_trait]
impl RepositoryFactory for PinnedIssuerRepositoryFactory {
    async fn create(&self) -> Result<BoxRepository, RepositoryError> {
        let mut repo = self.inner.create().await?;
        let current = repo
            .station_trust()
            .find_by_name_for_share(&self.binding.name)
            .await?;
        if !current.is_some_and(|current| {
            current.service_id == self.binding.service_id
                && current.canonical_endpoint == self.binding.canonical_endpoint
        }) {
            repo.cancel().await?;
            return Err(RepositoryError::from_error(std::io::Error::other(
                "native issuer original Station enrollment is unavailable or changed",
            )));
        }
        Ok(repo)
    }

    async fn read(&self) -> Result<BoxRepository, RepositoryError> {
        // Query-scoped pool reads cannot retain this row lock. Core issuer
        // reads are transactions and release them before any network wait.
        self.create().await
    }
}
