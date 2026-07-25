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
| `lib` | `LoginReqBody`, `LoginOutcome`, `ViewerInfo`, `SessionGrantKind`, `SessionGrantOneShotInfo`, `SessionGrantPrincipalServerInfo`, `LogoutOutcome`, `ProvidersOutcome`, `CurrentAccountInfo`, `ProviderInfo`, `LinkedAccount`, `LinkedAccountsOutcome`, `UnlinkOutcome`, `ChannelAvailability`, `ChannelPreference`, `NotificationPreferencesOutcome`, `UpdateNotificationPreferencesOutcome`, `PatchNotificationPreferencesOutcome`, `RegisterOutcome`, `ChangeRegistrationEmailOutcome`, `RecoveryStatusOutcome`, `RecoveryTicketStatusOutcome`, `DeviceLinkOutcome`, `WorkflowInboxItem`, `WorkflowInboxOutcome`, `PageInfo` | Coauth backend and frontend; Sodmin consumes `LogoutOutcome` | Coauth account UI/session workflow DTOs. Protocol session-grant payloads are not redefined here; these are product response projections and UI workflow envelopes. |
| `passkey` | `PasskeyAccountHint`, `PasskeyRegisterFinishRequestBody`, `PasskeyAuthFinishRequestBody`, `PasskeyRegisterStartOutcome`, `PasskeyRegisterFinishOutcome`, `PasskeyAuthStartOutcome`, `PasskeyAuthFinishOutcome` | Coauth backend and frontend | Coauth passkey ceremony transport DTOs for `/_coauth/account/auth/passkey/*`; browser WebAuthn objects remain opaque JSON owned by the WebAuthn ceremony, not Arkret wire types. |

## `coauth-admin-types`

| Module | Public types | Confirmed consumers | Ownership and spec/SDK conclusion |
| --- | --- | --- | --- |
| `account_admin` | `AdminAccountStatus`, `AdminAccountAttributes` | Coauth backend, Sodmin | Product administration projection for `/_coauth/admin/accounts`; no equivalent Arkret protocol DTO. |
| `account_claims_admin` | `AdminAccountClaimRecord`, `AdminAccountClaimsOutcome` | Coauth backend, Sodmin | Product account-claim inventory; free-form claim payload stays product-local. |
| `audit_admin` | `AuditSignatureStatus`, `AuditEntry`, `AuditFeedOutcome` | Coauth backend, Sodmin | Operator audit projection; not an Arkret event or audit-envelope replacement. |
| `bridge_admin` | `AdminBridgeDescribe`, `AdminBridgeRiskActionExamples`, `AdminBridgeRiskActionProposalExample`, `AdminBridgeRiskActionApprovalExample`, `AdminBridgeRiskActionExecuteExample` | Coauth backend, Sodmin | Typed `/_coauth/admin/bridge/describe` product discovery and request examples. Rollout versions, TODOs, and storage implementation metadata are forbidden. |
| `circle_capability_admin` | `CircleCapabilityAction`, `ParseCircleCapabilityActionError`, `RiskTier`, `CircleCapabilityGrant`, `CreateCircleCapabilityGrant`, `ListCircleCapabilityGrantsOutcome` | Coauth backend | Product administration subset for Circle grants. Action tokens and risk tiers are constrained by the current spec registry; the endpoint envelope remains Coauth-local. |
| `collaboration_capability_admin` | `CapabilityCategory`, `CollaborationCapabilityAction`, `ParseCollaborationCapabilityActionError`, `RiskTier`, `CollaborationCapabilityGrant`, `CollaborationCapabilityTemplate`, `CreateCollaborationCapabilityGrant`, `ListCollaborationCapabilityTemplatesOutcome`, `ListCollaborationCapabilityGrantsOutcome` | Coauth backend | Product administration subset for collaboration grants. Canonical action strings come from the spec registry; product grant/template envelopes are not protocol DTOs. |
| `connector_health` | `ConnectorHealthStatus`, `ConnectorHealthRow`, `ConnectorHealthOutcome` | Coauth backend, Sodmin | Deployment connector health projection; no Arkret protocol equivalent. |
| `did_binding_admin` | `DidBindingKind`, `DidBindingState`, `DidBindingVerificationStatus`, `DidBindingResolverMode`, `DidBindingResolverDescriptor`, `AccountDidBindingPreview`, `AdminAccountDidBinding`, `AdminAccountDidBindingsMeta`, `AdminAccountDidBindingsOutcome` | Coauth backend, Sodmin | Coauth DID-binding administration projection. DID values use SDK-owned identifier types at protocol boundaries; lifecycle/UI enums remain product-local. |
| `envelope` | `Resource`, `SelfLinks`, `PaginationLinks`, `PaginationMeta`, `SingleResourceMetaPage`, `SingleResourceMeta`, `SingleResource`, `SingleOutcome`, `PaginatedOutcome` | Coauth backend, Sodmin | Coauth admin JSON response envelope; not an Arkret protocol envelope. |
| `federation_admin` | `FederationPeerHealth`, `FederationStatusRow` | Coauth backend, Sodmin | Product deployment health view; not the Arkret federation wire model. |
| `integration_manifest_admin` | `IntegrationManifest`, `IntegrationManifestDependency`, `IntegrationManifestSurface` | Coauth backend, Sodmin | `/_coauth/account/integration/describe` product discovery. Only stable service, dependency, and surface data are allowed. |
| `notification_admin` | `NotificationChannelStatus`, `NotificationChannelsOutcome`, `NotificationTemplateEntry`, `NotificationTemplatesOutcome`, `PublishTemplateRequestBody`, `PublishedTemplateOutcome` | Coauth backend, Sodmin | Coauth notification operator API; no Arkret protocol equivalent. |
| `organization_admin` | `OrganizationBootstrapAuthorization`, `OrganizationDelegationStatus`, `OrganizationPrincipalControl`, `OrganizationDelegation`, `BootstrapAuthorizationInput`, `BootstrapOrganizationRequest`, `RecordOrganizationDelegationRequest`, `RenewOrganizationDelegationRequest`, `RotateOrganizationControllerRequest`, `IssueOrganizationStatementRequest`, `OrganizationControlView`, `ListOrganizationDelegationsOutcome` | Coauth backend, Sodmin | Product control-plane commands and projections. Embedded organization/capability fields reuse SDK collaboration models where specified. |
| `resource_models` | `UserEmail`, `OAuthSession`, `UserSession`, `UpstreamOAuthLink`, `UserRegistrationToken`, `UpstreamOAuthProvider`, `PersonalSession` | Coauth backend, Sodmin | Coauth persistence-backed admin resources projected as product DTOs; secrets are excluded from the wire shapes. |
| `risk_action` | `AccountRiskActionProposalRequestBody`, `AccountRiskActionApprovalRequestBody`, `AccountRiskActionExecuteRequestBody`, `AccountRiskActionProposalOutcome`, `AccountRiskActionApprovalOutcome`, `AccountRiskActionCurrentOutcome`, `AccountRiskActionHistoryOutcome`, `AccountRiskActionTransitionRecord` | Coauth backend, Sodmin | Durable Coauth operator workflow DTOs; state-store implementation details are not part of the contract. |

When the spec or SDK adds an equivalent canonical type, the matching local type
must be removed or reduced to a product-only wrapper that directly contains the
SDK type. Adding a public type requires updating this ledger in the same change;
the workspace boundary check rejects missing entries.
