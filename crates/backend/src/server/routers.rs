use coauth_data::UrlBuilder;
use coauth_templates::Templates;
use salvo::prelude::*;

use super::middleware::{OpenApiYaml, oidc_preflight_handler, public_oidc_browser_cors};
use crate::listener::ConnectionInfo;

pub(crate) fn build_human_router(router: Router, _templates: Templates) -> Router {
    use crate::handlers::oauth::authorization;
    use crate::handlers::{email_webhooks, spa, upstream_oauth};

    router
        .push(Router::with_path("/webhooks/email/{provider}").post(email_webhooks::post))
        // ── OAuth protocol endpoints (server-side redirects) ──
        .push(Router::with_path("/authorize").get(authorization::get))
        // ── Upstream OAuth (server-side redirect & callback) ──
        .push(
            Router::with_path("/upstream/authorize/{provider_id}")
                .get(upstream_oauth::authorize::get),
        )
        .push(
            Router::with_path("/upstream/callback/{provider_id}")
                .get(upstream_oauth::callback::handler)
                .post(upstream_oauth::callback::handler),
        )
        .push(Router::with_path("/upstream/link/{link_id}").get(spa::get))
        .push(
            Router::with_path("/upstream/backchannel-logout/{provider_id}")
                .post(upstream_oauth::backchannel_logout::post),
        )
        // ── Well-known redirect ──
        .push(
            Router::with_path("/.well-known/change-password").get(change_password_redirect_handler),
        )
        // ── SPA shell ──
        // Root & auth pages
        .push(Router::with_path("/").get(spa::get))
        .push(Router::with_path("/login").get(spa::get))
        .push(Router::with_path("/register").get(spa::get))
        .push(Router::with_path("/register/{**rest}").get(spa::get))
        .push(Router::with_path("/recover").get(spa::get))
        .push(Router::with_path("/recover/{**rest}").get(spa::get))
        .push(Router::with_path("/oauth/approval/{**rest}").get(spa::get))
        .push(Router::with_path("/link").get(spa::get))
        .push(Router::with_path("/device/{**rest}").get(spa::get))
        // Account pages (root-level frontend routes)
        .push(Router::with_path("/settings").get(spa::get))
        .push(Router::with_path("/sessions").get(spa::get))
        .push(Router::with_path("/sessions/{**rest}").get(spa::get))
        .push(Router::with_path("/security").get(spa::get))
        .push(Router::with_path("/notifications").get(spa::get))
        .push(Router::with_path("/identities").get(spa::get))
        .push(Router::with_path("/contacts").get(spa::get))
        .push(Router::with_path("/workflows").get(spa::get))
        .push(Router::with_path("/plan").get(spa::get))
        // Standalone pages
        .push(Router::with_path("/password/{**rest}").get(spa::get))
        .push(Router::with_path("/emails/{**rest}").get(spa::get))
        .push(Router::with_path("/clients/{**rest}").get(spa::get))
        .push(Router::with_path("/devices/{**rest}").get(spa::get))
}

pub(crate) fn build_oauth_router(router: Router) -> Router {
    use crate::handlers::oauth::{
        device, introspection, keys, registration, revoke, token, userinfo,
    };

    let cors = || public_oidc_browser_cors();

    router
        .push(
            Router::with_path("/oauth/keys.json")
                .hoop(cors())
                .get(keys::get),
        )
        .push(
            Router::with_path("/oauth/userinfo")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .get(userinfo::get)
                .post(userinfo::get),
        )
        .push(
            Router::with_path("/oauth/introspect")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(introspection::post),
        )
        .push(
            Router::with_path("/oauth/revoke")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(revoke::post),
        )
        .push(
            Router::with_path("/oauth/token")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(token::post),
        )
        .push(
            Router::with_path("/oauth/registration")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(registration::post),
        )
        .push(
            Router::with_path("/oauth/device")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(device::authorize::post),
        )
}
/// Mount the account/protocol API routes without the generated OpenAPI
/// documents. `build_account_api_router` layers the documents on top; the
/// in-process test harness mounts the same routes through this entry point so
/// the route table can never drift from production.
// Consumed only by the `#[cfg(test)]` test harness, so non-test builds see no
// caller.
#[allow(dead_code)]
pub(crate) fn build_account_api_routes(router: Router) -> Router {
    let (arkret_router, coauth_router) = account_api_subrouters();
    router.push(arkret_router).push(coauth_router)
}

pub(super) fn build_account_api_router(router: Router) -> Router {
    use crate::handlers::account::openapi;

    let (arkret_router, coauth_router) = account_api_subrouters();

    let docs_router = openapi::build_openapi_router(&coauth_router);

    // The `/.well-known/arkret/openapi.yaml` path is a *protocol-surface*
    // contract: it MUST publish the Arkret protocol API (`/_arkret/*`), not the
    // product-private admin API. Generate the protocol-face OpenAPI document
    // from `arkret_router` and serve it from the well-known path here, keeping
    // the admin document (`/_coauth/admin/openapi.yaml`) strictly separate.
    let arkret_doc = build_arkret_protocol_openapi_doc(&arkret_router);
    let arkret_doc_yaml = OpenApiYaml::from_doc(&arkret_doc);

    router
        .push(arkret_router)
        .push(coauth_router)
        .push(docs_router)
        .push(Router::with_path("/.well-known/arkret/openapi.yaml").get(arkret_doc_yaml))
}

fn account_api_subrouters() -> (Router, Router) {
    use crate::handlers::account::{
        agents, approval, auth, avatar, bootstrap_admin_status, emails, invite_relay,
        linked_accounts, notification_prefs, oauth_clients, password, recovery, register, sessions,
        site_config, strand, upstream_oauth, users, viewer,
    };
    use crate::handlers::{arkret, policy_check};

    let arkret_router = Router::with_path("/_arkret")
        .hoop(public_oidc_browser_cors())
        .push(Router::with_path("describe").get(arkret::server_describe))
        .push(Router::with_path("root/identity/describe").get(arkret::identity_describe))
        .push(Router::with_path("root/identity/resolve").post(arkret::identity_resolve))
        .push(Router::with_path("root/identity/document").get(arkret::identity_document))
        .push(
            Router::with_path("find/directory/resolve-handle")
                .post(arkret::directory_resolve_handle),
        )
        // Protocol surface for DPoP-bound session-grant rotation. The grant is
        // the (minutes-to-hours) refresh credential; an authorized device
        // proves possession of the key bound into the grant's `cnf.jkt` and
        // rotates onto a fresh grant without re-running OIDC — this is what
        // lets a device session live for days while access bearers stay short.
        // It is a spec operation (service-http-binding session-grants surface),
        // so it is exposed under `/_arkret` (not the product-private `/_coauth`)
        // and clients reach it as a protocol path.
        .push(
            Router::with_path("gate/account/authentication-handoffs")
                .options(oidc_preflight_handler)
                .post(arkret::create_account_handoff),
        )
        .push(
            Router::with_path("gate/account/onboarding")
                .options(oidc_preflight_handler)
                .get(arkret::account_onboarding_snapshot),
        )
        .push(
            Router::with_path("gate/account/did-binding-challenges")
                .options(oidc_preflight_handler)
                .post(arkret::issue_did_binding_challenge),
        )
        .push(
            Router::with_path("gate/account/identity-binding-challenges")
                .options(oidc_preflight_handler)
                .post(arkret::issue_identity_binding_challenge),
        )
        .push(
            Router::with_path("gate/account/identity-abandonment-challenges")
                .options(oidc_preflight_handler)
                .post(arkret::issue_identity_abandonment_challenge),
        )
        .push(
            Router::with_path("gate/account/identity-abandonments")
                .options(oidc_preflight_handler)
                .post(arkret::abandon_identity_creation),
        )
        .push(
            Router::with_path("gate/account/controller-gate-attestations")
                .post(arkret::issue_controller_gate_attestation),
        )
        .push(
            Router::with_path("gate/account/register")
                .options(oidc_preflight_handler)
                .post(arkret::account_register_endpoint),
        )
        .push(
            Router::with_path("gate/account/session-grants/refresh")
                .options(oidc_preflight_handler)
                .post(arkret::refresh_session_grant),
        )
        .push(
            Router::with_path("gate/account/session-grants/revoke")
                .options(oidc_preflight_handler)
                .post(arkret::revoke_session_grant_endpoint),
        )
        // Auth-side hard logout sub-operation (account-lifecycle §4.1).
        // This is an internal Account Authority -> Auth Server service call:
        // the client-visible hard logout endpoint is the Principal/Account
        // Authority `POST /_arkret/gate/account/logout`, and clients must not
        // call this path directly.
        .push(
            Router::with_path("gate/account/auth-sessions/logout")
                .post(arkret::logout_auth_session),
        )
        // Server-to-server session-grant introspection (RFC 7662-style): the
        // Principal Server validating a presented grant calls this to learn
        // whether it is active and to obtain the session public key for RFC 9421
        // PoP verification. It is a spec operation
        // (`ak.gate.account.command.introspect_session_grant`), so it lives under
        // `/_arkret`; the handler self-authorizes via the configured
        // `session_grant_introspection_bearer` (or an admin scope).
        .push(
            Router::with_path("gate/account/session-grants/introspect")
                .post(arkret::introspect_session_grant),
        )
        // Canonical Account Authority session-grant issuance. Human issuance
        // consumes a holder-bound AccountHandoff plus accepted-device PoP;
        // Agent issuance uses its separate scoped proof variant. OIDC codes
        // are consumed only while creating the AccountHandoff.
        .push(
            Router::with_path("gate/account/session-grants")
                .options(oidc_preflight_handler)
                .post(arkret::issue_session_grant_endpoint),
        )
        // AKP-0008 §4.5 runtime key pairing
        // (`ak.gate.account.command.pair_agent_key`): the agent runtime submits
        // its locally-generated public key + proof-of-possession; coauth
        // validates the PoP, writes a durable agent key authorization, and fans
        // `ak.agent.key.authorize` out to soland.
        .push(
            Router::with_path("gate/account/agent-key-pair")
                .options(oidc_preflight_handler)
                .post(agents::post_agent_key_pair),
        )
        .push(
            Router::with_path("gate/account/recovery-session-grants/issue")
                .options(oidc_preflight_handler)
                .post(arkret::issue_recovery_completion_grant_endpoint),
        )
        // Self-service account erasure entry point
        // (`ak.gate.account.command.request_erasure`, account-lifecycle.md
        // §8.1). Accepted directly by the Account Authority on the gate
        // surface: high-risk fresh-authentication gate, durable intent
        // record, and the existing `erasure_pending` issuance flow all live
        // inside this service.
        .push(
            Router::with_path("gate/account/erasure-requests")
                .options(oidc_preflight_handler)
                .post(arkret::request_account_erasure),
        )
        .push(
            Router::with_path("peer/account-status/resolve")
                .post(arkret::resolve_account_status),
        )
        .push(Router::with_path("self/policy/check").post(policy_check::post_policy_check))
        .push(Router::with_path("{**rest}").goal(arkret_not_found));

    let mut coauth_router = Router::with_path("/_coauth")
        .hoop(public_oidc_browser_cors())
        // Product-private surface only. Protocol-standard Arkret endpoints
        // are served solely under `/_arkret` above — clients speaking the
        // protocol must use `/_arkret`, never a `/_coauth` path.
        .push(
            // `account/identity/primary-handle` is a coauth product-private
            // path (not a spec operation). It deliberately avoids the protocol
            // trust-surface classifier `root/identity/` (reserved for the
            // canonical `/_arkret/root/identity/{describe,resolve,document}`
            // Principal Server identity-root operations), mirroring how
            // `account/session-grants` below avoids the `gate/` classifier.
            Router::with_path("account/identity/primary-handle")
                .patch(crate::handlers::account::primary_handle::patch_primary_handle_preference),
        )
        .push(
            // Product-private account-management UI surface: `list` and
            // `{id}/revoke`. `introspect` is the spec operation served under
            // `/_arkret` above; the DPoP-bound `refresh` / hard-logout `revoke`
            // are protocol operations and live under `/_arkret` only.
            //
            // Product-private paths deliberately avoid the protocol
            // trust-surface classifier `gate/`; they live under
            // `/_coauth/account/*` so the `gate/account/*` vocabulary stays
            // reserved for the canonical `/_arkret` operations.
            Router::with_path("account/session-grants")
                .get(crate::handlers::account::session_grants::list_session_grants)
                .push(Router::with_path("{id}/revoke").post(crate::handlers::account::session_grants::revoke_session_grant)),
        )
        // Viewer
        .push(
            Router::with_path("self/viewer")
                .get(viewer::get_viewer)
                .push(Router::with_path("overview").get(viewer::get_viewer_overview))
                .push(Router::with_path("security").get(viewer::get_security_summary))
                .push(Router::with_path("password").post(password::set_password))
                .push(Router::with_path("profile").patch(users::patch_profile))
                .push(Router::with_path("avatar").post(avatar::upload_avatar))
                .push(Router::with_path("avatar/{user_id}").get(avatar::get_avatar))
                .push(Router::with_path("deactivate").post(users::deactivate_user))
                .push(
                    Router::with_path("preferences")
                        .get(notification_prefs::get_notification_preferences)
                        .patch(notification_prefs::patch_notification_preferences),
                ),
        )
        .push(Router::with_path("self/bootstrap-admin-status").get(bootstrap_admin_status::get))
        .push(
            Router::with_path("self/passkeys")
                .get(auth::passkey::list)
                .push(Router::with_path("{id}").patch(auth::passkey::rename))
                .push(Router::with_path("{id}/revoke").post(auth::passkey::revoke)),
        )
        // Site config
        .push(Router::with_path("self/site-config").get(site_config::get))
        // Sessions
        .push(Router::with_path("self/sessions/{id}").get(sessions::get_session))
        .push(Router::with_path("self/browser-sessions/{id}").delete(sessions::end_browser_session))
        .push(Router::with_path("self/oauth-sessions").get(sessions::list_oauth_sessions))
        .push(
            Router::with_path("self/oauth-sessions/{id}")
                .delete(sessions::end_oauth_session)
                .push(Router::with_path("name").put(sessions::set_oauth_session_name)),
        )
        // OAuth clients
        .push(Router::with_path("self/oauth-clients/{id}").get(oauth_clients::get_client))
        // Password recovery
        .push(
            Router::with_path("account/password-recovery")
                .push(Router::with_path("{ticket}").get(password::get_recovery_ticket_status))
                .push(Router::with_path("set").post(password::set_password_by_recovery))
                .push(Router::with_path("resend").post(password::resend_recovery_email)),
        )
        // Email authentication
        .push(
            Router::with_path("account/email-auth")
                .push(Router::with_path("start").post(emails::start_email_auth))
                .push(
                    Router::with_path("{id}")
                        .get(emails::get_email_auth)
                        .push(Router::with_path("complete").post(emails::complete_email_auth))
                        .push(Router::with_path("resend").post(emails::resend_email_auth_code)),
                ),
        )
        // User emails
        .push(Router::with_path("self/user-emails/{id}").delete(emails::remove_email))
        .push(
            Router::with_path("account/integration/describe").get(auth::integration_describe),
        )
        // Auth (login, logout, providers, registration, recovery)
        //
        // The product-private OIDC bridge endpoints (`bridge/describe`,
        // `oidc/browser-bridge/session`, `oidc/exchange/describe`,
        // `oidc/exchange`) were removed (account-lifecycle §4.1,
        // service-surface.md §2.5.1). Clients now run standard OIDC discovery
        // + authorize against the issuer and exchange the code only through
        // `POST /_arkret/gate/account/authentication-handoffs`. Passkey + standard OIDC
        // (`/authorize`, `/oauth/token`, `/.well-known/openid-configuration`)
        // are unchanged.
        .push(
            Router::with_path("account/auth")
                .push(Router::with_path("login").post(auth::login))
                .push(
                    Router::with_path("passkey")
                        .push(
                            Router::with_path("register/start").post(auth::passkey::register_start),
                        )
                        .push(
                            Router::with_path("register/finish")
                                .post(auth::passkey::register_finish),
                        )
                        .push(Router::with_path("auth/start").post(auth::passkey::auth_start))
                        .push(Router::with_path("auth/finish").post(auth::passkey::auth_finish)),
                )
                .push(Router::with_path("logout").post(auth::logout))
                .push(Router::with_path("providers").get(auth::providers))
                // Registration
                .push(
                    Router::with_path("register")
                        .post(register::post_register)
                        .push(
                            Router::with_path("{id}")
                                .get(register::get_registration)
                                .push(
                                    Router::with_path("verify-email")
                                        .post(register::post_verify_email),
                                )
                                .push(
                                    Router::with_path("verify-phone")
                                        .post(register::post_verify_phone),
                                )
                                .push(
                                    Router::with_path("resend-verification")
                                        .post(register::post_resend_verification),
                                )
                                .push(
                                    Router::with_path("change-email")
                                        .post(register::post_change_email),
                                )
                                .push(
                                    Router::with_path("display-name")
                                        .post(register::post_display_name),
                                )
                                .push(Router::with_path("finish").post(register::post_finish)),
                        ),
                )
                // Account recovery
                .push(
                    Router::with_path("recovery")
                        .push(Router::with_path("start").post(recovery::post_recovery_start))
                        .push(Router::with_path("{id}").get(recovery::get_recovery).push(
                            Router::with_path("resend").post(recovery::post_recovery_resend),
                        )),
                ),
        )
        // OAuth approval
        .push(
            Router::with_path("self/oauth/authorization-grants/{grant_id}/decision")
                .get(approval::oauth_approval_get)
                .post(approval::oauth_approval_post),
        )
        // Invite relay (consent-gated forward to target principal)
        .push(Router::with_path("self/account/invites/relay").post(invite_relay::post_invite_relay))
        // Device code link & approval
        .push(Router::with_path("self/device-link").get(approval::device_link_get))
        .push(
            Router::with_path("self/device-grants/{id}/decision")
                .get(approval::device_approval_get)
                .post(approval::device_approval_post),
        )
        // Linked accounts
        .push(
            Router::with_path("self/linked-accounts")
                .get(linked_accounts::list_linked_accounts)
                .push(Router::with_path("{id}").delete(linked_accounts::unlink_account)),
        )
        // Upstream OAuth link
        .push(
            Router::with_path("self/upstream-oauth/link/{id}")
                .get(upstream_oauth::get_link)
                .post(upstream_oauth::post_link),
        )
        // Strand engine
        .push(
            Router::with_path("self/strand")
                .push(Router::with_path("{slug}/start").post(strand::start_strand))
                .push(
                    Router::with_path("session/{id}")
                        .get(strand::get_strand_session)
                        .push(Router::with_path("respond").post(strand::respond_strand)),
                ),
        )
        // AKP-0008 personal-agent controller approval. Internal
        // server-to-server endpoint: accepts only soland / sodmin
        // static bearers. Issues a `accountability_grant` payload
        // referencing the agent principal + capability set.
        .push(
            Router::with_path("self/agents/{id}/accountability-grant")
                .post(agents::post_accountability_grant),
        );

    #[cfg(debug_assertions)]
    if arkret::test_endpoints_enabled() {
        coauth_router = coauth_router.push(
            Router::with_path("account/test/debug/issue-dpop-grant")
                .post(arkret::debug_issue_dpop_grant),
        );
    }

    (arkret_router, coauth_router)
}

#[handler]
async fn arkret_not_found(req: &Request, res: &mut Response) {
    let request_id = res
        .headers()
        .get(crate::server::ARKRET_REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("ak:request:{}", uuid::Uuid::now_v7()));
    if let Some(allowed) = arkret_allowed_methods(req.uri().path()) {
        res.status_code(StatusCode::METHOD_NOT_ALLOWED);
        if let Ok(value) = http::HeaderValue::from_str(allowed) {
            res.headers_mut().insert(http::header::ALLOW, value);
        }
        res.render(Json(
            arkret_wire::ErrorEnvelope::new(
                arkret_wire::ErrorCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )
            .with_request_id(&request_id),
        ));
    } else {
        res.status_code(StatusCode::NOT_FOUND);
        res.render(Json(
            arkret_wire::ErrorEnvelope::new(
                arkret_wire::ErrorCode::UNRECOGNIZED_ENDPOINT,
                "unrecognized Arkret endpoint",
            )
            .with_request_id(&request_id),
        ));
    }
}

fn arkret_allowed_methods(path: &str) -> Option<&'static str> {
    match path {
        "/_arkret/describe"
        | "/_arkret/root/identity/describe"
        | "/_arkret/root/identity/document" => Some("GET"),
        "/_arkret/gate/account/onboarding" => Some("GET, OPTIONS"),
        "/_arkret/root/identity/resolve"
        | "/_arkret/find/directory/resolve-handle"
        | "/_arkret/gate/account/auth-sessions/logout"
        | "/_arkret/gate/account/session-grants/introspect"
        | "/_arkret/self/policy/check" => Some("POST"),
        "/_arkret/gate/account/authentication-handoffs"
        | "/_arkret/gate/account/did-binding-challenges"
        | "/_arkret/gate/account/identity-binding-challenges"
        | "/_arkret/gate/account/identity-abandonment-challenges"
        | "/_arkret/gate/account/identity-abandonments"
        | "/_arkret/gate/account/controller-gate-attestations"
        | "/_arkret/gate/account/register"
        | "/_arkret/gate/account/session-grants/refresh"
        | "/_arkret/gate/account/session-grants/revoke"
        | "/_arkret/gate/account/session-grants"
        | "/_arkret/gate/account/agent-key-pair"
        | "/_arkret/gate/account/erasure-requests"
        | "/_arkret/gate/account/recovery-session-grants/issue" => Some("POST, OPTIONS"),
        _ => None,
    }
}

pub(super) fn build_arkret_protocol_openapi_doc(arkret_router: &Router) -> salvo::oapi::OpenApi {
    salvo::oapi::OpenApi::new("Arkret Protocol API", env!("CARGO_PKG_VERSION"))
        .merge_router(arkret_router)
}

/// Mount the admin API routes without the generated OpenAPI document and the
/// Swagger UI. `build_admin_router` layers those on top; the in-process test
/// harness mounts the same routes through this entry point so the route table
/// can never drift from production.
// Consumed only by the `#[cfg(test)]` test harness, so non-test builds see no
// caller.
#[allow(dead_code)]
pub(crate) fn build_admin_routes(router: Router) -> Router {
    router.push(admin_subrouter())
}

pub(super) fn build_admin_router(router: Router) -> Router {
    let admin_router = admin_subrouter();

    // Generate OpenAPI spec and Swagger UI for the admin API
    let admin_doc = build_admin_openapi_doc(&admin_router);
    let admin_doc_yaml = OpenApiYaml::from_doc(&admin_doc);

    router
        .push(admin_router)
        .push(admin_doc.clone().into_router("/api-doc/admin/openapi.json"))
        .push(Router::with_path("/_coauth/admin/openapi.yaml").get(admin_doc_yaml))
        .push(
            salvo::oapi::swagger_ui::SwaggerUi::new("/api-doc/admin/openapi.json")
                .into_router("admin-swagger-ui"),
        )
}

fn admin_subrouter() -> Router {
    use crate::handlers::admin::v1::{
        account_dids, accounts, audit_feed, circle_capabilities, claims,
        collaboration_capabilities, connector_health, devices, invite_quarantine,
        notification_channels, notification_templates, oauth_clients, oauth_clients_i18n,
        oauth_clients_register, oauth_sessions, organizations, personal_sessions, policy_checks,
        policy_data, site_config, upstream_oauth_links, upstream_oauth_providers, user_emails,
        user_registration_tokens, user_sessions, version,
    };

    Router::with_path("/_coauth/admin")
        // Version
        .push(Router::with_path("version").get(version::handler))
        // Site config
        .push(Router::with_path("site-config").get(site_config::handler))
        // Operational health
        .push(Router::with_path("connector-health").get(connector_health::handler))
        .push(Router::with_path("notification-channels").get(notification_channels::handler))
        // Notification templates
        .push(
            Router::with_path("notification-templates")
                .get(notification_templates::list_handler)
                .push(Router::with_path("publish").post(notification_templates::publish_handler)),
        )
        // Audit feed
        .push(Router::with_path("audit-feed").get(audit_feed::handler))
        // AKP-0007 ak.circle.* capability grants (P2B.2). Wire shape is in
        // coauth-admin-types::circle_capability_admin; persistence is durable.
        .push(
            Router::with_path("circles/capabilities")
                .get(circle_capabilities::list_handler)
                .post(circle_capabilities::create_handler)
                .push(Router::with_path("{grant_id}").delete(circle_capabilities::revoke_handler)),
        )
        // Collaboration capability grants for pin/RSVP and Realm policy facets.
        .push(
            Router::with_path("collaboration/capabilities")
                .get(collaboration_capabilities::list_handler)
                .push(
                    Router::with_path("templates")
                        .get(collaboration_capabilities::templates_handler),
                )
        )
        // COA-ORG: organization principal control + delegation management.
        // Wire shapes are in coauth-admin-types::organization_admin + the SDK
        // ak.realm.organization payload; persistence is durable.
        .push(
            Router::with_path("organizations")
                .push(Router::with_path("bootstrap").post(organizations::bootstrap_handler))
                .push(
                    Router::with_path("{org_did}")
                        .get(organizations::get_handler)
                        .push(
                            Router::with_path("rotate-controller")
                                .post(organizations::rotate_controller_handler),
                        )
                        .push(
                            Router::with_path("statements")
                                .post(organizations::issue_statement_handler),
                        )
                        .push(
                            Router::with_path("delegations")
                                .get(organizations::list_delegations_handler)
                                .post(organizations::record_delegation_handler)
                                .push(
                                    Router::with_path("{delegation_ref}")
                                        .push(
                                            Router::with_path("revoke")
                                                .post(organizations::revoke_delegation_handler),
                                        )
                                        .push(
                                            Router::with_path("renew")
                                                .post(organizations::renew_delegation_handler),
                                        ),
                                ),
                        ),
                ),
        )
        // Invite-quarantine outbox (C10.E §6.1 default-profile path)
        .push(
            Router::with_path("invite-quarantine")
                .get(invite_quarantine::list_invite_quarantine)
                .push(
                    Router::with_path("{id}/resolve")
                        .post(invite_quarantine::resolve_invite_quarantine),
                ),
        )
        // Arkret accounts
        .push(Router::with_path("bridge/describe").get(accounts::admin_bridge_describe))
        .push(
            Router::with_path("accounts")
                .get(accounts::list_accounts)
                .post(accounts::create::add_account)
                .push(
                    Router::with_path("by-username/{username}")
                        .get(accounts::get_account_by_username),
                )
                .push(Router::with_path("batch-invite").post(accounts::create::batch_invite))
                .push(
                    Router::with_path("{id}")
                        .get(accounts::get_account)
                        .patch(accounts::update::update_account)
                        .push(
                            Router::with_path("set-password")
                                .post(accounts::security::set_password),
                        )
                        .push(Router::with_path("claims").get(accounts::list_account_claims))
                        .push(
                            Router::with_path("risk-action/history")
                                .get(accounts::risk_action::list_history),
                        )
                        .push(
                            Router::with_path("risk-action/current")
                                .get(accounts::risk_action::get_current),
                        )
                        .push(Router::with_path("risk-action").post(accounts::risk_action::propose))
                        .push(
                            Router::with_path("risk-action/{proposal_id}/approve")
                                .post(accounts::risk_action::approve),
                        )
                        .push(
                            Router::with_path("risk-action/{proposal_id}/execute")
                                .post(accounts::risk_action::execute),
                        )
                        .push(Router::with_path("lock").post(accounts::lock_account))
                        .push(Router::with_path("disable").post(accounts::disable_account))
                        .push(Router::with_path("erase").post(accounts::erase_account))
                        .push(Router::with_path("reset-recovery").post(accounts::reset_recovery))
                        .push(
                            Router::with_path("dids")
                                .get(account_dids::list_account_dids)
                                .post(account_dids::add_account_did)
                                .push(
                                    Router::with_path("{did_id}")
                                        .delete(account_dids::remove_account_did),
                                ),
                        )
                        .push(
                            Router::with_path("devices")
                                .get(devices::list_account_devices)
                                .push(
                                    Router::with_path("{device_id}/revoke")
                                        .post(devices::revoke_account_device),
                                ),
                        ),
                ),
        )
        // The former `/_coauth/admin/users/*` tree is gone: accounts (above)
        // is the single admin resource tree over the users table, and the
        // unaccountable immediate risk-action executor was replaced by the
        // accounts propose -> approve -> execute workflow.
        // User emails
        .push(
            Router::with_path("user-emails")
                .get(user_emails::list_emails)
                .post(user_emails::add_email)
                .push(
                    Router::with_path("{id}")
                        .get(user_emails::get_email)
                        .patch(user_emails::update_email)
                        .delete(user_emails::delete_email),
                ),
        )
        // User sessions
        .push(
            Router::with_path("user-sessions")
                .get(user_sessions::list_sessions)
                .push(
                    Router::with_path("{id}")
                        .get(user_sessions::get_session)
                        .push(Router::with_path("finish").post(user_sessions::finish_session)),
                ),
        )
        // OAuth sessions
        .push(
            Router::with_path("oauth-sessions")
                .get(oauth_sessions::list_sessions)
                .push(
                    Router::with_path("{id}")
                        .get(oauth_sessions::get_session)
                        .push(Router::with_path("finish").post(oauth_sessions::finish_session)),
                ),
        )
        // OAuth client localised metadata
        .push(
            Router::with_path("oauth-clients").push(
                Router::with_path("{id}").push(
                    Router::with_path("localized-metadata")
                        .get(oauth_clients::get_localized_metadata)
                        .put(oauth_clients::replace_localized_metadata),
                ),
            ),
        )
        // RFC 7591 admin dynamic client registration
        .push(Router::with_path("oauth/clients/register").post(oauth_clients_register::register))
        // Admin-curated OAuth client display name + description per locale.
        .push(
            Router::with_path("oauth/clients/{id}/i18n")
                .get(oauth_clients_i18n::get_i18n)
                .post(oauth_clients_i18n::upsert_i18n),
        )
        // Personal sessions
        .push(
            Router::with_path("personal-sessions")
                .get(personal_sessions::list_sessions)
                .post(personal_sessions::add_session)
                .push(
                    Router::with_path("{id}")
                        .get(personal_sessions::get_session)
                        .push(
                            Router::with_path("regenerate")
                                .post(personal_sessions::regenerate_session),
                        )
                        .push(Router::with_path("revoke").post(personal_sessions::revoke_session)),
                ),
        )
        // Arkret devices
        .push(
            Router::with_path("devices")
                .get(devices::list_devices)
                .push(Router::with_path("{id}/revoke").post(devices::revoke_device)),
        )
        // User registration tokens
        .push(
            Router::with_path("user-registration-tokens")
                .get(user_registration_tokens::list_tokens)
                .post(user_registration_tokens::add_token)
                .push(
                    Router::with_path("{id}")
                        .get(user_registration_tokens::get_token)
                        .put(user_registration_tokens::update_token)
                        .push(
                            Router::with_path("revoke")
                                .post(user_registration_tokens::revoke_token),
                        )
                        .push(
                            Router::with_path("unrevoke")
                                .post(user_registration_tokens::unrevoke_token),
                        ),
                ),
        )
        // Upstream OAuth providers
        .push(
            Router::with_path("upstream-oauth-providers")
                .get(upstream_oauth_providers::list_providers)
                .post(upstream_oauth_providers::add_provider)
                .push(
                    Router::with_path("{id}")
                        .get(upstream_oauth_providers::get_provider)
                        .patch(upstream_oauth_providers::update_provider)
                        .delete(upstream_oauth_providers::delete_provider)
                        .push(
                            Router::with_path("disable")
                                .post(upstream_oauth_providers::disable_provider),
                        )
                        .push(
                            Router::with_path("enable")
                                .post(upstream_oauth_providers::enable_provider),
                        ),
                ),
        )
        // Upstream OAuth links
        .push(
            Router::with_path("upstream-oauth-links")
                .get(upstream_oauth_links::list_links)
                .post(upstream_oauth_links::add_link)
                .push(
                    Router::with_path("{id}")
                        .get(upstream_oauth_links::get_link)
                        .patch(upstream_oauth_links::update_link)
                        .delete(upstream_oauth_links::delete_link),
                ),
        )
        // Policy data
        .push(
            Router::with_path("policy-data")
                .push(Router::with_path("latest").get(policy_data::get_latest))
                .push(Router::with_path("{id}").get(policy_data::get_by_id))
                .put(policy_data::set_data),
        )
        // Arkret claims and policy checks
        .push(
            Router::with_path("claims")
                .post(claims::issue_claim)
                .push(Router::with_path("status").get(claims::list_claim_status))
                .push(Router::with_path("{id}/revoke").post(claims::revoke_claim)),
        )
        .push(
            Router::with_path("policy-checks")
                .push(Router::with_path("dry-run").post(policy_checks::dry_run)),
        )
        .push(
            Router::with_path("policy-decision-audits")
                .push(Router::with_path("{id}").get(policy_checks::get_signed_decision_audit)),
        )
}

pub(super) fn build_admin_openapi_doc(admin_router: &Router) -> salvo::oapi::OpenApi {
    salvo::oapi::OpenApi::new("coauth Admin API", env!("CARGO_PKG_VERSION"))
        .merge_router(admin_router)
}

#[handler]
pub(super) async fn change_password_redirect_handler(depot: &Depot) -> impl Writer + use<> {
    use crate::app_state::DepotExt;

    let url_builder = depot.get_url_builder().cloned();
    Redirect::found(absolute_redirect_location(
        url_builder.as_ref(),
        "/password/change",
    ))
}

pub(super) fn absolute_redirect_location(url_builder: Option<&UrlBuilder>, path: &str) -> String {
    url_builder.map_or_else(
        || path.to_owned(),
        |url_builder| url_builder.absolute_url(path).to_string(),
    )
}

#[handler]
pub(super) async fn connection_info_handler(req: &Request) -> String {
    if let Some(conn_info) = req.extensions().get::<ConnectionInfo>() {
        format!("{conn_info:?}")
    } else {
        "No connection info available".to_owned()
    }
}
