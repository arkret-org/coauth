# Get an access token

`coauth` includes helper scripts in `misc/` for interactive CLI/admin access
through the OAuth Device Authorization Grant:

- `misc/device-code-grant.sh` for POSIX shells. It requires `sh`, `jq`, and
  `curl`.
- `misc/device-code-grant.ps1` for PowerShell on Windows. It does not require
  `jq`.

The scripts use the standard OIDC discovery document at
`/.well-known/openid-configuration`, dynamically register a native public
client, and default to the `urn:coauth:admin` scope when no scope is passed.

```sh
sh ./misc/device-code-grant.sh https://auth.example.com/
```

```powershell
pwsh -File ./misc/device-code-grant.ps1 https://auth.example.com/
```

This prints a verification URL and user code. Finish the browser flow, then the
script prints the token response.

## Common scopes

Use `urn:coauth:admin` for the stable coauth admin API:

```sh
sh ./misc/device-code-grant.sh https://auth.example.com/ urn:coauth:admin
```

Use Cokret scopes for Cokret-native integrations:

```sh
sh ./misc/device-code-grant.sh https://auth.example.com/ urn:cokret:admin:* urn:cokret:principal-server:session.bind
```

## Automation

For non-interactive automation, prefer the OAuth client credentials grant
with a confidential client:

```sh
TOKEN=$(curl -sS -X POST https://auth.example.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=urn:coauth:admin" \
  | jq -r '.access_token')
```

Access tokens are short-lived by default. Store them as secrets and revoke the
underlying session or client credentials when automation is decommissioned.
