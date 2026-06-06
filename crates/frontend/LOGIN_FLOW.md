# Login Flow Cross-Check

This note captures the coauth-side login flow that `sodmin` should align with.
No `sodmin` files are modified by this slice; the shared admin bridge boundary
continues to live in `coauth-admin-types`.

## SPA Flow

| SPA action | Frontend path | Backend route |
| --- | --- | --- |
| Load login methods | `GET /auth/providers` | `GET /_coauth/gate/account/auth/providers` |
| Password login | `POST /auth/login` | `POST /_coauth/gate/account/auth/login` |
| Upstream OAuth login | provider `authorize_url` from providers response | backend-managed upstream authorize route |
| Continue OAuth grant after login | `kind=continue_authorization_grant&id=...` query | frontend routes to `Route::OAuthApproval { grant_id }` |
| Register during grant continuation | store `post_auth_kind` and `post_auth_id` in `sessionStorage` | registration finish resumes the same grant context |

The `/login` server-rendered page and the Dioxus SPA both resolve available
upstream providers from the same account-auth service layer. The SPA uses the
JSON API routes under `/_coauth/gate/account/auth/*`; the server-rendered fallback posts form
data to `/login` and then calls the same password-login service path.

## Sodmin Boundary

`sodmin` should not post login credentials through the admin bridge. The
admin bridge is for operator/admin workflows and is described by
`GET /_coauth/admin/bridge/describe`. Interactive user login should target the
account-auth endpoints above or follow the provider `authorize_url` returned by
`GET /_coauth/gate/account/auth/providers`.

## Local Check

```powershell
rg -n '"/auth/providers"|"/auth/login"|continue_authorization_grant|post_auth_kind|post_auth_id' crates/frontend/src/pages/login.rs
rg -n 'Router::with_path\("providers"\)|pub async fn login|pub async fn providers|POST /_coauth/gate/account/auth/login|GET /_coauth/gate/account/auth/providers' crates/backend/src/handlers/account/auth.rs crates/backend/src/server.rs
```
