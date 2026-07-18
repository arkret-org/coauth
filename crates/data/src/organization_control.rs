//! Organization-control persistence boundary.

pub use coauth_data_model::{
    OrganizationBootstrapAuthorization, OrganizationDelegation, OrganizationDelegationStatus,
    OrganizationPrincipalControl, PRINCIPAL_CONTROL_REALM_BOOTSTRAP_PURPOSE,
};

pub use crate::storage::organization_control::*;
