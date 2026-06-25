use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::Clock;
use coauth_data::audit::{
    AccountSecurityEvent, AdminOperation, AdminOperationLog, SecurityEventType,
};
use rand_core::RngCore;
use serde_json::Value;
use ulid::Ulid;

use crate::repository_impl;

/// Parameters used when creating a new admin operation log entry.
#[derive(Debug, Clone)]
pub struct NewAdminOperationLog {
    admin_user_id: Ulid,
    operation: AdminOperation,
    resource_type: String,
    resource_id: Option<Ulid>,
    details: Value,
    ip_address: Option<std::net::IpAddr>,
    user_agent: Option<String>,
    audit_signature: Option<String>,
}

impl NewAdminOperationLog {
    /// Create a new admin operation log draft.
    #[must_use]
    pub fn new(
        admin_user_id: Ulid,
        operation: AdminOperation,
        resource_type: impl Into<String>,
        details: Value,
    ) -> Self {
        Self {
            admin_user_id,
            operation,
            resource_type: resource_type.into(),
            resource_id: None,
            details,
            ip_address: None,
            user_agent: None,
            audit_signature: None,
        }
    }

    /// Set the target resource ID.
    #[must_use]
    pub fn with_resource_id(mut self, resource_id: Ulid) -> Self {
        self.resource_id = Some(resource_id);
        self
    }

    /// Set the client IP address.
    #[must_use]
    pub fn with_ip_address(mut self, ip_address: std::net::IpAddr) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    /// Set the client user-agent string.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Attach a base64url-unpadded detached signature over the
    /// canonical-JSON form of the row. Optional during the staged
    /// rollout; new signed writers should prefer inserting first and
    /// then calling [`AuditRepository::set_admin_operation_signature`]
    /// so the signature can bind repository-generated metadata.
    #[must_use]
    pub fn with_audit_signature(mut self, signature: impl Into<String>) -> Self {
        self.audit_signature = Some(signature.into());
        self
    }

    /// The detached audit-row signature, if any.
    #[must_use]
    pub fn audit_signature(&self) -> Option<&str> {
        self.audit_signature.as_deref()
    }

    /// The admin user who performed the operation.
    #[must_use]
    pub fn admin_user_id(&self) -> Ulid {
        self.admin_user_id
    }

    /// The type of operation performed.
    #[must_use]
    pub fn operation(&self) -> &AdminOperation {
        &self.operation
    }

    /// The target resource type.
    #[must_use]
    pub fn resource_type(&self) -> &str {
        &self.resource_type
    }

    /// The target resource ID, if any.
    #[must_use]
    pub fn resource_id(&self) -> Option<Ulid> {
        self.resource_id
    }

    /// Structured details about the operation.
    #[must_use]
    pub fn details(&self) -> &Value {
        &self.details
    }

    /// The client IP address, if any.
    #[must_use]
    pub fn ip_address(&self) -> Option<std::net::IpAddr> {
        self.ip_address
    }

    /// The client user-agent string, if any.
    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
}

/// Parameters used when creating a new account security event.
#[derive(Debug, Clone)]
pub struct NewAccountSecurityEvent {
    user_id: Ulid,
    event_type: SecurityEventType,
    metadata: Value,
    ip_address: Option<std::net::IpAddr>,
    user_agent: Option<String>,
}

impl NewAccountSecurityEvent {
    /// Create a new account security event draft.
    #[must_use]
    pub fn new(user_id: Ulid, event_type: SecurityEventType, metadata: Value) -> Self {
        Self {
            user_id,
            event_type,
            metadata,
            ip_address: None,
            user_agent: None,
        }
    }

    /// Set the client IP address.
    #[must_use]
    pub fn with_ip_address(mut self, ip_address: std::net::IpAddr) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    /// Set the client user-agent string.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// The user account this event relates to.
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }

    /// The type of security event.
    #[must_use]
    pub fn event_type(&self) -> &SecurityEventType {
        &self.event_type
    }

    /// Structured event metadata.
    #[must_use]
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }

    /// The client IP address, if any.
    #[must_use]
    pub fn ip_address(&self) -> Option<std::net::IpAddr> {
        self.ip_address
    }

    /// The client user-agent string, if any.
    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
}

/// Filter criteria for querying admin operation logs.
#[derive(Debug, Clone, Default)]
pub struct AdminOperationFilter {
    /// Only return operations performed by this admin user.
    pub admin_user_id: Option<Ulid>,
    /// Only return operations on this resource type.
    pub resource_type: Option<String>,
    /// Only return operations targeting this specific resource id.
    pub resource_id: Option<Ulid>,
    /// Only return operations created after this time.
    pub created_after: Option<DateTime<Utc>>,
    /// Only return operations created before this time.
    pub created_before: Option<DateTime<Utc>>,
    /// Maximum number of results to return.
    pub limit: Option<usize>,
}

impl AdminOperationFilter {
    /// Create a new empty filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by admin user ID.
    #[must_use]
    pub fn for_admin_user(mut self, admin_user_id: Ulid) -> Self {
        self.admin_user_id = Some(admin_user_id);
        self
    }

    /// Filter by resource type.
    #[must_use]
    pub fn for_resource_type(mut self, resource_type: impl Into<String>) -> Self {
        self.resource_type = Some(resource_type.into());
        self
    }

    /// Filter by a specific target resource id (the `resource_id` column).
    ///
    /// Use this to scope an audit read to a single account/device/etc. at the
    /// query layer instead of pulling a wide `with_limit` page and filtering in
    /// memory, which silently truncates older rows once the global page cap is
    /// exceeded.
    #[must_use]
    pub fn for_resource(mut self, resource_id: Ulid) -> Self {
        self.resource_id = Some(resource_id);
        self
    }

    /// Filter by created-after timestamp.
    #[must_use]
    pub fn created_after(mut self, after: DateTime<Utc>) -> Self {
        self.created_after = Some(after);
        self
    }

    /// Filter by created-before timestamp.
    #[must_use]
    pub fn created_before(mut self, before: DateTime<Utc>) -> Self {
        self.created_before = Some(before);
        self
    }

    /// Limit the number of results.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Repository for admin operation logs and account security events.
#[async_trait]
pub trait AuditRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Record a new admin operation log entry.
    async fn add_admin_operation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAdminOperationLog,
    ) -> Result<AdminOperationLog, Self::Error>;

    /// Look up an admin operation log entry by id.
    async fn lookup_admin_operation(
        &mut self,
        id: Ulid,
    ) -> Result<Option<AdminOperationLog>, Self::Error>;

    /// Set the detached signature for an existing admin operation log entry.
    async fn set_admin_operation_signature(
        &mut self,
        id: Ulid,
        audit_signature: &str,
    ) -> Result<AdminOperationLog, Self::Error>;

    /// List admin operation log entries, optionally filtered by admin user.
    async fn list_admin_operations(
        &mut self,
        filter: AdminOperationFilter,
    ) -> Result<Vec<AdminOperationLog>, Self::Error>;

    /// Count admin operation log entries matching the given filter.
    async fn count_admin_operations(
        &mut self,
        filter: AdminOperationFilter,
    ) -> Result<usize, Self::Error>;

    /// Record a new account security event.
    async fn add_security_event(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAccountSecurityEvent,
    ) -> Result<AccountSecurityEvent, Self::Error>;

    /// List security events for a specific user.
    async fn list_security_events(
        &mut self,
        user_id: Ulid,
    ) -> Result<Vec<AccountSecurityEvent>, Self::Error>;
}

repository_impl!(AuditRepository:
    async fn add_admin_operation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAdminOperationLog,
    ) -> Result<AdminOperationLog, Self::Error>;
    async fn lookup_admin_operation(
        &mut self,
        id: Ulid,
    ) -> Result<Option<AdminOperationLog>, Self::Error>;
    async fn set_admin_operation_signature(
        &mut self,
        id: Ulid,
        audit_signature: &str,
    ) -> Result<AdminOperationLog, Self::Error>;
    async fn list_admin_operations(
        &mut self,
        filter: AdminOperationFilter,
    ) -> Result<Vec<AdminOperationLog>, Self::Error>;
    async fn count_admin_operations(
        &mut self,
        filter: AdminOperationFilter,
    ) -> Result<usize, Self::Error>;
    async fn add_security_event(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAccountSecurityEvent,
    ) -> Result<AccountSecurityEvent, Self::Error>;
    async fn list_security_events(
        &mut self,
        user_id: Ulid,
    ) -> Result<Vec<AccountSecurityEvent>, Self::Error>;
);
