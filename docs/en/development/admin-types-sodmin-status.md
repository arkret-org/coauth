# Admin Types / Sodmin Pairing Status

This is a local status record for the `coauth-admin-types` extraction and the
remaining `sodmin` pairing work. It is not a release note and does not publish
anything outside this repository.

## Current Coauth State

- `coauth-admin-types` is the local source of truth for the shared admin wire
  shapes that were previously duplicated in backend handlers and sodmin shims.
- The extraction covers the local modules called out by the readiness plan:
  `applets_admin`, `bridge_admin`, `federation_admin`, and
  `space_policy_admin`.
- The admin bridge discovery payload now comes from
  `coauth_admin_types::admin_bridge_describe(...)`; backend handlers no longer
  maintain a second copy of the bridge paths or risk-action examples.
- `bridge_admin` owns the durable proposal risk-action example constructors
  used by the backend discovery response and by the OpenAPI schema example
  annotations.
- The English Admin API documentation includes the admin bridge discovery
  response and the three risk-action request examples.

## Sodmin Pairing Record

The local coauth half is ready for sodmin to replace its inline decoder shims
with imports from `coauth-admin-types`. The pairing should be done in sodmin,
not in this repository.

Expected sodmin follow-up:

- Replace inline copies of the applet, federation, space-policy, account,
  bridge, and risk-action admin DTOs with `coauth-admin-types` imports where
  crate boundaries allow it.
- Keep any sodmin-only presentation model separate from the wire DTOs.
- Confirm sodmin decodes `GET /_coauth/admin/bridge/describe` with typed
  `risk_action_examples` instead of opaque JSON values.
- Confirm the admin bridge does not own user login credentials; interactive
  login remains on the account-auth endpoints documented in
  `crates/frontend/LOGIN_STRAND.md`.

## Local Evidence

- `crates/admin-types/src/lib.rs`
- `crates/admin-types/src/bridge_admin.rs`
- `crates/backend/src/handlers/admin/v1/accounts.rs`
- `docs/en/topics/admin-api.md`
- `crates/frontend/LOGIN_STRAND.md`

## Acceptance For Closing The Cross-Repo Pairing

- Coauth tests pass with the local `arkret` SDK version aligned.
- Sodmin compiles with `coauth-admin-types` and no local duplicate DTOs for the
  surfaces listed above.
- A sodmin smoke run can fetch `/.well-known/arkret/openapi.yaml` and
  `GET /_coauth/admin/bridge/describe`.
- No release tag, GitHub release, crate publication, or image push is required
  for this local status record.
