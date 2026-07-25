# Coauth product contract ownership

This ledger covers the public Rust types intentionally shared through
`coauth-account-types` and `coauth-admin-types`. These crates own only
`/_coauth/*` product surfaces. Arkret protocol types remain owned by
`arkret-rust-sdk`; endpoint DTO fields reuse SDK models where the spec defines
them.

The producer is the Coauth backend unless noted otherwise. “Sodmin” means the
type is part of the deployment-local administration boundary, not a public
Arkret protocol commitment.

## `coauth-account-types`

| Module | Public types | Confirmed consumers | Ownership and spec/SDK conclusion |
| --- | --- | --- | --- |
| `lib` | `LoginReqBody`, `LoginOutcome`, `ViewerInfo`, `SessionGrantKind`, `SessionGrantOneShotInfo`, `SessionGrantPrincipalServerInfo`, `LogoutOutcome`, `ProvidersOutcome`, `CurrentAccountInfo`, `ProviderInfo`, `LinkedAccount`, `LinkedAccountsOutcome`, `UnlinkOutcome`, `ChannelAvailability`, `ChannelPreference`, `NotificationPreferencesOutcome`, `UpdateNotificationPreferencesOutcome`, `RegisterOutcome`, `ChangeRegistrationEmailOutcome`, `RecoveryStatusOutcome`, `RecoveryTicketStatusOutcome`, `DeviceLinkOutcome`, `WorkflowInboxItem`, `WorkflowInboxOutcome`, `PageInfo` | Coauth backend and frontend; Sodmin consumes `LogoutOutcome` | Coauth account UI/session workflow DTOs. Protocol session-grant payloads are not redefined here; these are product response projections and UI workflow envelopes. |
| `passkey` | `PasskeyAccountHint`, `PasskeyRegisterFinishRequestBody`, `PasskeyAuthFinishRequestBody`, `PasskeyRegisterStartOutcome`, `PasskeyRegisterFinishOutcome`, `PasskeyAuthStartOutcome`, `PasskeyAuthFinishOutcome` | Coauth backend and frontend | Coauth passkey ceremony transport DTOs for `/_coauth/account/auth/passkey/*`; browser WebAuthn objects remain opaque JSON owned by the WebAuthn ceremony, not Arkret wire types. |

## `coauth-admin-types`

| Module | Public types | Confirmed consumers | Ownership and spec/SDK conclusion |
| --- | --- | --- | --- |
| `account_admin` | `AdminAccountStatus`, `AdminAccountAttributes` | Coauth backend, Sodmin | Product administration projection for `/_coauth/admin/accounts`; no equivalent Arkret protocol DTO. |
| `account_claims_admin` | `AdminAccountClaimRecord`, `AdminAccountClaimsOutcome` | Coauth backend, Sodmin | Product account-claim inventory; free-form claim payload stays product-local. |
| `audit_admin` | `AuditSignatureStatus`, `AuditEntry`, `AuditFeedOutcome` | Coauth backend, Sodmin | Operator audit projection; not an Arkret event or audit-envelope replacement. |
| `bridge_admin` | `AdminBridgeDescribe`, `AdminBridgeRiskActionExamples`, `AdminBridgeRiskActionProposalExample`, `AdminBridgeRiskActionApprovalExample`, `AdminBridgeRiskActionExecuteExample` | Coauth backend, Sodmin | Typed `/_coauth/admin/bridge/describe` product discovery and request examples. Rollout versions, TODOs, and storage implementation metadata are forbidden. |
| `circle_capability_admin` | `CapabilityActionId` (SDK re-export), `CapabilityRiskTier` (SDK re-export), `CircleCapabilityGrant`, `CreateCircleCapabilityGrant`, `ListCircleCapabilityGrantsOutcome` | Coauth backend | Product administration subset for Circle grants. Action identity and risk metadata come directly from the spec-generated SDK registry; Coauth only validates which canonical ids belong to this product surface. |
| `collaboration_capability_admin` | `CapabilityActionId` (SDK re-export), `CapabilityRiskTier` (SDK re-export), `CollaborationCapabilityGrant`, `CollaborationCapabilityTemplate`, `CreateCollaborationCapabilityGrant`, `ListCollaborationCapabilityTemplatesOutcome`, `ListCollaborationCapabilityGrantsOutcome` | Coauth backend | Product administration subset for collaboration grants. Template category/profile/event mapping metadata is projected from the SDK registry; product grant/template envelopes remain Coauth-local. |
| `connector_health` | `ConnectorHealthStatus`, `ConnectorHealthRow`, `ConnectorHealthOutcome` | Coauth backend, Sodmin | Deployment connector health projection; no Arkret protocol equivalent. |
| `did_binding_admin` | `DidBindingKind`, `DidBindingState`, `DidBindingVerificationStatus`, `DidBindingResolverMode`, `DidBindingResolverDescriptor`, `AdminAccountDidBinding`, `AdminAccountDidBindingsMeta`, `AdminAccountDidBindingsOutcome` | Coauth backend, Sodmin | Coauth DID-binding administration projection. DID values use SDK-owned identifier types at protocol boundaries; lifecycle/UI enums remain product-local. |
| `envelope` | `Resource`, `SelfLinks`, `PaginationLinks`, `PaginationMeta`, `SingleResourceMetaPage`, `SingleResourceMeta`, `SingleResource`, `SingleOutcome`, `PaginatedOutcome` | Coauth backend, Sodmin | Coauth admin JSON response envelope; not an Arkret protocol envelope. |
| `integration_manifest_admin` | `IntegrationManifest`, `IntegrationManifestDependency`, `IntegrationManifestSurface` | Coauth backend, Sodmin | `/_coauth/account/integration/describe` product discovery. Only stable service, dependency, and surface data are allowed. |
| `notification_admin` | `NotificationChannelStatus`, `NotificationChannelsOutcome`, `NotificationTemplateEntry`, `NotificationTemplatesOutcome`, `PublishTemplateRequestBody`, `PublishedTemplateOutcome` | Coauth backend, Sodmin | Coauth notification operator API; no Arkret protocol equivalent. |
| `organization_admin` | `OrganizationBootstrapAuthorization`, `OrganizationDelegationStatus`, `OrganizationPrincipalControl`, `OrganizationDelegation`, `BootstrapAuthorizationInput`, `BootstrapOrganizationRequest`, `RecordOrganizationDelegationRequest`, `RenewOrganizationDelegationRequest`, `RotateOrganizationControllerRequest`, `IssueOrganizationStatementRequest`, `OrganizationControlView`, `ListOrganizationDelegationsOutcome` | Coauth backend, Sodmin | Product control-plane commands and projections. Embedded organization/capability fields reuse SDK collaboration models where specified. |
| `resource_models` | `UserEmail`, `OAuthSession`, `UserSession`, `UpstreamOAuthLink`, `UserRegistrationToken`, `UpstreamOAuthProvider`, `PersonalSession` | Coauth backend, Sodmin | Coauth persistence-backed admin resources projected as product DTOs; secrets are excluded from the wire shapes. |
| `risk_action` | `AccountRiskActionProposalRequestBody`, `AccountRiskActionApprovalRequestBody`, `AccountRiskActionExecuteRequestBody`, `AccountRiskActionProposalOutcome`, `AccountRiskActionApprovalOutcome`, `AccountRiskActionCurrentOutcome`, `AccountRiskActionHistoryOutcome`, `AccountRiskActionTransitionRecord` | Coauth backend, Sodmin | Durable Coauth operator workflow DTOs; state-store implementation details are not part of the contract. |

### Audited provider-local dependencies

`coauth-admin-types` depends on `coauth-data-model`. This dependency is allowed
because the latter is a storage-neutral model leaf: its dependency closure
contains SDK/schema models, serde/chrono, and optional schema derives, but no
database adapter, network client, queue, repository implementation, or service
crate. The admin contract uses it only for:

- canonical SDK-backed `CapabilityActionId` / `CapabilityRiskTier` identities;
- pure Circle/collaboration product-subset rules;
- organization lifecycle enums and explicit domain-record-to-wire mappings.

The full domain grant and organization records are not publicly re-exported by
`coauth-admin-types`. Any new provider-local dependency, or any implementation
dependency introduced transitively beneath `coauth-data-model`, requires a new
audit and allowlist update.

When the spec or SDK adds an equivalent canonical type, the matching local type
must be removed or reduced to a product-only wrapper that directly contains the
SDK type. Adding a public type requires updating this ledger in the same change;
the workspace boundary check rejects missing entries.
