//! Shared serde types for the coauth account UI API surface.
//!
//! Scope: coauth-private browser/account REST endpoints served under
//! `/_coauth`, such as `/_coauth/gate/account/auth/login`. Protocol-level
//! Arkret endpoints served under `/_arkret` continue to use types from
//! `arkret-rust-sdk`.

pub mod passkey;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct LoginReqBody {
    pub handle: String,
    pub password: String,
    /// Audience the client wants the issued session grant to be bound to.
    /// Must exactly match a configured principal-server audience. When
    /// omitted, the caller is implicitly accepting the deployment's only
    /// configured server name.
    #[serde(default)]
    pub audience: Option<String>,
    /// Solved CAPTCHA token, supplied when the deployment has a CAPTCHA
    /// provider configured.
    #[serde(default)]
    pub captcha_token: Option<String>,
    /// Device the issued principal-server session grant is bound to. Required
    /// when password-login session grants are enabled.
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct LoginOutcome {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewer: Option<ViewerInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_grant: Option<SessionGrantOneShotInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl LoginOutcome {
    pub fn success(
        viewer: Option<ViewerInfo>,
        session_grant: Option<SessionGrantOneShotInfo>,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            status: "success".to_owned(),
            error: None,
            viewer,
            session_grant,
            warnings,
        }
    }

    pub fn error(error: impl Into<String>) -> Self {
        Self {
            status: "error".to_owned(),
            error: Some(error.into()),
            viewer: None,
            session_grant: None,
            warnings: Vec::new(),
        }
    }

    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ViewerInfo {
    pub id: String,
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    pub federated_handle: String,
    pub principal_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantKind {
    PrincipalSession,
    PushRegister,
    DevicePairing,
    AdminBridge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantOneShotInfo {
    pub kind: SessionGrantKind,
    pub id: String,
    pub grant_jwt: String,
    pub session_public_key: String,
    pub expires_at: String,
    pub audience: String,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_server: Option<SessionGrantPrincipalServerInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantPrincipalServerInfo {
    pub name: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct LogoutOutcome {
    pub status: String,
}

impl LogoutOutcome {
    pub fn success() -> Self {
        Self {
            status: "success".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ProvidersOutcome {
    pub providers: Vec<ProviderInfo>,
    pub password_login_enabled: bool,
    pub password_registration_enabled: bool,
    #[serde(default)]
    pub account_recovery_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_account: Option<CurrentAccountInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct CurrentAccountInfo {
    pub id: String,
    pub username: String,
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ProviderInfo {
    pub id: String,
    #[serde(default)]
    pub human_name: Option<String>,
    #[serde(default)]
    pub brand_name: Option<String>,
    pub authorize_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_login_without_session_grant_decodes() {
        let outcome: LoginOutcome = serde_json::from_value(serde_json::json!({
            "status": "success",
            "viewer": {
                "id": "user:01KVVVKSMNEAFSMKH4HCXD1E7T",
                "handle": "alice",
                "federated_handle": "alice:auth.local.host",
                "principal_id": "alice@auth.local.host",
                "display_name": "alice"
            },
            "session_grant": null,
            "warnings": [
                "password_login_session_grants_disabled; use the OIDC/passkey bridge"
            ]
        }))
        .expect("password login response decodes without viewer.did");

        assert_eq!(outcome.status, "success");
        assert_eq!(
            outcome.viewer.as_ref().expect("viewer").handle.as_str(),
            "alice"
        );
        assert_eq!(outcome.viewer.as_ref().expect("viewer").did, None);
        assert!(outcome.session_grant.is_none());
        assert_eq!(outcome.warnings.len(), 1);
    }
}
