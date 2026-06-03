# Admin API

`coauth` provides a REST-like API for administrators and `sodmin` to manage
accounts, sessions, devices, claims, OAuth clients, notification channels,
connectors, and policy data. The API is only available to administrators and
trusted automation.

## Enabling the API

The API isn't exposed by default, and must be added to either a public or a private HTTP listener.
It is considered safe to expose the API to the public, as access to it is gated by `urn:coauth:admin` or `urn:cokret:admin:*`.

To enable the API, tweak the [`http.listeners`](../reference/configuration.md#httplisteners) configuration section to add the `adminapi` resource:

```yaml
http:
  listeners:
    - name: web
      resources:
        # Other public resources
        - name: discovery
        # …
        - name: adminapi
      binds:
        - address: "[::]:8080"
    # or to a separate, internal listener:
    - name: internal
      resources:
        # Other internal resources
        - name: health
        - name: prometheus
        # …
        - name: adminapi
      binds:
        - host: localhost
          port: 8081
```

## Reference documentation

The API is documented using the [OpenAPI specification](https://spec.openapis.org/oas/v3.1.0).
When the admin API resource is enabled, `coauth` serves the same generated
specification at these runtime paths:

- `GET /_cokret/local/admin/openapi.yaml` for the Cokret-native admin API contract.
- `GET /.well-known/cokret/openapi.yaml` for discovery by `sodmin` and
  service automation.
- `GET /api-doc/admin/openapi.json` for legacy Swagger tooling.
- `GET /admin-swagger-ui/` for the hosted Swagger UI.

## Admin bridge discovery examples

`GET /_cokret/local/admin/bridge/describe` publishes the typed admin bridge contract
used by `sodmin` and by local automation. The response shape and request body
examples are generated from `coauth-admin-types::bridge_admin`, so the OpenAPI
schema, backend response, and Rust consumers share one source of truth.

```json
{
  "contract": "cx.contract.coauth_admin_bridge.v1",
  "version": "0.2.0-durable-proposals",
  "api_base_path": "/_cokret/local/admin",
  "accounts_path": "/_cokret/local/admin/accounts",
  "account_detail_path_template": "/_cokret/local/admin/accounts/{account_id}",
  "account_dids_path_template": "/_cokret/local/admin/accounts/{account_id}/dids",
  "account_claims_path_template": "/_cokret/local/admin/accounts/{account_id}/claims",
  "account_session_grants_path_template": "/_cokret/local/admin/accounts/{account_id}/session-grants",
  "risk_action_path_template": "/_cokret/local/admin/accounts/{account_id}/risk-action",
  "risk_action_current_path_template": "/_cokret/local/admin/accounts/{account_id}/risk-action/current",
  "risk_action_history_path_template": "/_cokret/local/admin/accounts/{account_id}/risk-action/history",
  "risk_action_approve_path_template": "/_cokret/local/admin/accounts/{account_id}/risk-action/{proposal_id}/approve",
  "risk_action_execute_path_template": "/_cokret/local/admin/accounts/{account_id}/risk-action/{proposal_id}/execute",
  "risk_action_state_store_kind": "pg_risk_action_proposals_with_admin_audit_trail",
  "risk_action_approval_mode": "durable_proposal_required",
  "risk_action_examples": {
    "proposal_request": {
      "action": "lock",
      "reason": "suspicious session recovery detected",
      "ticket": "INC-2026-0504"
    },
    "approve_request": {
      "action": "lock",
      "ticket": "INC-2026-0504",
      "approved_by": "did:web:admin.example",
      "approval_note": "approved for controlled execution",
      "approval_proof_jws": "protected..signature"
    },
    "execute_request": {
      "action": "lock",
      "ticket": "INC-2026-0504",
      "execution_note": "execute via controlled mutation worker"
    }
  },
  "todos": []
}
```

The same example request bodies apply to the risk-action workflow:

```bash
curl -X POST \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"lock","reason":"suspicious session recovery detected","ticket":"INC-2026-0504"}' \
  "https://auth.example.com/_cokret/local/admin/accounts/$ACCOUNT_ID/risk-action"

curl -X POST \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"lock","ticket":"INC-2026-0504","approved_by":"did:web:admin.example","approval_note":"approved for controlled execution","approval_proof_jws":"protected..signature"}' \
  "https://auth.example.com/_cokret/local/admin/accounts/$ACCOUNT_ID/risk-action/$PROPOSAL_ID/approve"

curl -X POST \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"lock","ticket":"INC-2026-0504","execution_note":"execute via controlled mutation worker"}' \
  "https://auth.example.com/_cokret/local/admin/accounts/$ACCOUNT_ID/risk-action/$PROPOSAL_ID/execute"
```

`approval_proof_jws` is a detached EdDSA JWS (`protected..signature`) by
`approved_by`. Its detached payload is the canonical JSON transcript binding
`proposal_id`, `account_id`, `action`, `ticket`, `approval_note`, and
`approved_by`.

The Cokret-native admin surface now includes `GET /_cokret/local/admin/accounts`,
`GET /_cokret/local/admin/accounts/{id}`, `POST /_cokret/local/admin/accounts/{id}/lock`,
and `POST /_cokret/local/admin/accounts/{id}/disable`. DID bindings, device
administration, claim issuance/revocation, policy dry-run, and signed policy
decision audit routes are present in OpenAPI as guarded endpoints. Device
inventory is derived from persisted session grants and device revoke audit
records; policy dry-runs persist a signed decision audit record that can be
looked up through the decision-audit route.

## Authentication

All requests to the admin API are gated either using access tokens obtained using OAuth grants,
or using personal access tokens (which must currently be issued through the Admin API).

They must have the [`urn:coauth:admin`](../reference/scopes.md#urncoauthadmin) scope or a Cokret admin scope.

### User-interactive tools

If the intent is to build admin tools where the administrator logs in themselves, interactive grants like the [authorization code] grant or the [device authorization] grant should be used.

In this case, whether the user can request admin access or not is defined by the `can_request_admin` attribute of the user.

To try it out in Swagger UI, a client can be defined statically in the configuration file like this:

```yaml
clients:
  - client_id: 01J44Q10GR4AMTFZEEF936DTCM
    # For the authorization_code grant, Swagger UI uses the client_secret_post authentication method
    client_auth_method: client_secret_post
    client_secret: wie9oh2EekeeDeithei9Eipaeh2sohte
    redirect_uris:
      # The Swagger UI callback hosted by the service
      - https://auth.example.com/admin-swagger-ui/oauth-callback
```

Then, in Swagger UI, click on the "Authorize" button.
In the modal, enter the client ID and client secret **in the `authorizationCode` section**, select the `urn:coauth:admin` scope and click on the "Authorize" button.

### Automated tools

If the intent is to build tools that are not meant to be used by humans, the client credentials grant should be used.

In this case, the client must be listed in the [`policy.data.admin_clients`](../reference/configuration.md#policy) configuration option.

```yaml
policy:
  data:
    admin_clients:
      - 01J44QC8BCY7FCFM7WGHQGKMTJ
```

To try it out in Swagger UI, a client can be defined statically in the configuration file like this:

```yaml
clients:
  - client_id: 01J44QC8BCY7FCFM7WGHQGKMTJ
    # For the client_credentials grant, Swagger UI uses the client_secret_basic authentication method
    client_auth_method: client_secret_basic
    client_secret: eequie6Oth4Ip2InahT5zuQu8OuPohLi
```

Then, in Swagger UI, click on the "Authorize" button.
In the modal, enter the client ID and client secret **in the `clientCredentials` section**, select the `urn:coauth:admin` scope and click on the "Authorize" button.


## General API shape

The API takes inspiration from the [JSON API](https://jsonapi.org/) specification for its request and response shapes.

### Single resource

When querying a single resource, the response is generally shaped like this:

```json
{
  "data": {
    "type": "type-of-the-resource",
    "id": "unique-id-for-the-resource",
    "attributes": {
      "some-attribute": "some-value"
    },
    "links": {
      "self": "/_cokret/local/admin/type-of-the-resource/unique-id-for-the-resource"
    }
  },
  "links": {
    "self": "/_cokret/local/admin/type-of-the-resource/unique-id-for-the-resource"
  }
}
```

### List of resources

When querying a list of resources, the response is generally shaped like this:

```json
{
  "meta": {
    "count": 42
  },
  "data": [
    {
      "type": "type-of-the-resource",
      "id": "unique-id-for-the-resource",
      "attributes": {
        "some-attribute": "some-value"
      },
      "links": {
        "self": "/_cokret/local/admin/type-of-the-resource/unique-id-for-the-resource"
      }
    },
    { "...": "..." },
    { "...": "..." }
  ],
  "links": {
    "self": "/_cokret/local/admin/type-of-the-resource?page[first]=10&page[after]=some-id",
    "first": "/_cokret/local/admin/type-of-the-resource?page[first]=10",
    "last": "/_cokret/local/admin/type-of-the-resource?page[last]=10",
    "next": "/_cokret/local/admin/type-of-the-resource?page[first]=10&page[after]=some-id",
    "prev": "/_cokret/local/admin/type-of-the-resource?page[last]=10&page[before]=some-id"
  }
}
```

The `meta` will have the total number of items in it, and the `links` object contains the links to the next and previous pages, if any.

Pagination is cursor-based, where the ID of items is used as the cursor.
Resources can be paginated forwards using the `page[after]` and `page[first]` parameters, and backwards using the `page[before]` and `page[last]` parameters.

### Error responses

Error responses will use a 4xx or 5xx status code, with the following shape:

```json
{
  "errors": [
    {
      "title": "Error title"
    }
  ]
}
```

Well-known error codes are not yet specified.

Session and session-grant endpoints expose token metadata such as client ID,
audience, scope, expiry, revocation state, and last activity. They do not return
stored JWTs, refresh tokens, session private keys, or provider secrets in list
and detail responses. Personal access tokens are only returned immediately after
creation or regeneration.

## Example

With the following configuration:

```yaml
clients:
  - client_id: 01J44RKQYM4G3TNVANTMTDYTX6
    client_auth_method: client_secret_basic
    client_secret: phoo8ahneir3ohY2eigh4xuu6Oodaewi

policy:
  data:
    admin_clients:
      - 01J44RKQYM4G3TNVANTMTDYTX6
```

`curl` example to list the users that are not locked and have the `can_request_admin` flag set to `true`:

```bash
CLIENT_ID=01J44RKQYM4G3TNVANTMTDYTX6
CLIENT_SECRET=phoo8ahneir3ohY2eigh4xuu6Oodaewi

# Get an access token
curl \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=urn:coauth:admin" \
  https://auth.example.com/oauth/token \
  | jq -r '.access_token' \
  | read -r ACCESS_TOKEN

# List users (The -g flag prevents curl from interpreting the brackets in the URL)
curl \
  -g \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  'https://auth.example.com/_cokret/local/admin/users?filter[can_request_admin]=true&filter[status]=active&page[first]=100' \
  | jq
```

<details>
<summary>
Sample output
</summary>

```json
{
  "meta": {
    "count": 2
  },
  "data": [
    {
      "type": "user",
      "id": "01J2KDPHTZYW3TAT1SKVAD63SQ",
      "attributes": {
        "username": "kilgore-trout",
        "created_at": "2024-07-12T12:11:46.911578Z",
        "locked_at": null,
        "can_request_admin": true
      },
      "links": {
        "self": "/_cokret/local/admin/users/01J2KDPHTZYW3TAT1SKVAD63SQ"
      }
    },
    {
      "type": "user",
      "id": "01J3G5W8MRMBJ93ZYEGX2BN6NK",
      "attributes": {
        "username": "quentin",
        "created_at": "2024-07-23T16:13:04.024378Z",
        "locked_at": null,
        "can_request_admin": true
      },
      "links": {
        "self": "/_cokret/local/admin/users/01J3G5W8MRMBJ93ZYEGX2BN6NK"
      }
    }
  ],
  "links": {
    "self": "/_cokret/local/admin/users?filter[can_request_admin]=true&filter[status]=active&page[first]=100",
    "first": "/_cokret/local/admin/users?filter[can_request_admin]=true&filter[status]=active&page[first]=100",
    "last": "/_cokret/local/admin/users?filter[can_request_admin]=true&filter[status]=active&page[last]=100"
  }
}
```

</details>

## Realm classification — Principal Control vs Collaboration

CXP-0007 (cokret-spec commit `44abbd6`) made the distinction between two
realm classes explicit. Every admin route belongs to one of them:

- **Principal Control Realm** — identity, device, handle, claim, DID
  binding, OAuth client, registration token, upstream-link, password,
  session-grant management. Operators who hold capabilities here can
  alter who the principal *is*.
- **Collaboration Realm** — Spaces, Flows, Circles, membership, content
  policy. Operators who hold capabilities here govern what the principal
  *does together with other principals*. The six CXP-0007
  `cx.circle.*` capability actions live in this class.

| Route prefix                                              | Class                  |
|-----------------------------------------------------------|------------------------|
| `/_cokret/local/admin/accounts/*`                                | Principal Control      |
| `/_cokret/local/admin/users/*`                                   | Principal Control      |
| `/_cokret/local/admin/accounts/{id}/dids`                        | Principal Control      |
| `/_cokret/local/admin/accounts/{id}/claims`                      | Principal Control      |
| `/_cokret/local/admin/accounts/{id}/session-grants`              | Principal Control      |
| `/_cokret/local/admin/accounts/{id}/risk-action*`                | Principal Control      |
| `/_cokret/local/admin/oauth-clients*`                            | Principal Control      |
| `/_cokret/local/admin/upstream-oauth-*`                          | Principal Control      |
| `/_cokret/local/admin/user-registration-tokens*`                 | Principal Control      |
| `/_cokret/local/admin/devices`                                   | Principal Control      |
| `/_cokret/local/admin/passkeys`                                  | Principal Control      |
| `/_cokret/local/admin/personal-sessions`                         | Principal Control      |
| `/_cokret/local/admin/user-sessions`                             | Principal Control      |
| `/_cokret/local/admin/oauth-sessions`                            | Principal Control      |
| `/_cokret/local/admin/circles/capabilities*`                     | **Collaboration**      |
| `/_cokret/local/admin/notification-*`                            | Cross-cutting (audit)  |
| `/_cokret/local/admin/audit-feed`                                | Cross-cutting (audit)  |
| `/_cokret/local/admin/invite-quarantine*`                        | Cross-cutting (audit)  |
| `/_cokret/local/admin/site-config`                               | Cross-cutting (config) |

This classification is informational today — gating is still done by the
single `urn:coauth:admin` / `urn:cokret:admin:*` scope. The next round
of the rollout will split these into per-class scopes so that an
operator can be granted Collaboration-only access without being able to
mutate identity state.

## CXP-0007 `cx.circle.*` capability grants

The Collaboration class exposes a typed grant surface for the six
CXP-0007 capability actions:

| action                        | risk   | required constraint        |
|-------------------------------|--------|----------------------------|
| `ck.circle.create`            | medium | (none)                     |
| `ck.circle.manage`            | medium | `allowed_circle_ids`       |
| `ck.circle.member.add`        | low    | (none)                     |
| `ck.circle.member.manage`     | medium | `allowed_circle_ids`       |
| `ck.circle.member.add.others` | high   | `allowed_circle_ids`       |
| `ck.circle.audit`             | high   | (paired with audit check)  |

Endpoints:

```text
GET    /_cokret/local/admin/circles/capabilities
POST   /_cokret/local/admin/circles/capabilities
DELETE /_cokret/local/admin/circles/capabilities/{grant_id}
```

Request / response shapes are defined in
[`coauth_admin_types::circle_capability_admin`](https://github.com/cokret/coauth/blob/main/crates/admin-types/src/circle_capability_admin.rs).
See `_todos_all.md` (P2B.2) for the persistence backlog.

[authorization code]: ../topics/authorization.md#authorization-code-grant
[device authorization]: ../topics/authorization.md#device-authorization-grant
