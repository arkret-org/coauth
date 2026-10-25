# Login flow

The Glory account UI retains the account service API boundary:

| Action | Request |
| --- | --- |
| Discover methods and login hint | `GET /_coauth/account/auth/providers` with the entry query |
| Password sign-in | `POST /_coauth/account/auth/login` |
| Passkey ceremony | `/_coauth/account/auth/passkey/*` |
| Upstream sign-in | Provider `authorize_url`, preserving entry query parameters |
| Registration | `POST /_coauth/account/auth/register` and registration step endpoints |

`src/pages/auth.rs` owns identifier/password stages. A supplied login hint fixes
the selected account; otherwise users can switch accounts without losing the
continuation. Provider discovery failures retain a password fallback and an
explicit retry. Mutations expose busy state and visible error alerts.

`src/post_auth_continuation.rs` parses entry parameters into shared
`PostAuthAction` values and stores the continuation in session storage. Password
login, passkey login, and registration completion use `ui::auth_success` to
resume OAuth/device approval, account management, password change, or upstream
linking. Registration sends the typed continuation to the backend.

Interactive account credentials go to the account API, while the admin bridge
serves operator workflows. `tests/run.cjs` checks sign-in retry, fixed hints,
provider query preservation, and grant continuation.
