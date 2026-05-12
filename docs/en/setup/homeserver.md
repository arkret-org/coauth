# Principal Server configuration

coauth now runs as the Contrix Auth Server. Downstream Principal Servers such as
Soland consume OAuth/OIDC tokens and Contrix session grants; coauth no longer
connects to the retired delegated-auth adapter.

## Configure Soland as a Principal Server

Declare each trusted Principal Server in the `contrix.principal_servers`
section:

```yaml
contrix:
  principal_servers:
    - name: soland
      audience: https://soland.example.com/api
      endpoint: https://soland.example.com/
      did: did:web:soland.example.com

matrix:
  enabled: false
  homeserver: example.com
```

- `name`: operator-facing identifier for the Principal Server.
- `audience`: token/session-grant audience expected by that server.
- `endpoint`: base URL advertised through Contrix/OIDC discovery.
- `did`: optional DID advertised for the Principal Server.

The `matrix` section is retained only for legacy account-domain compatibility.
Keep `enabled: false` for new Contrix deployments.

## Discovery

coauth publishes Principal Server metadata through the standard OpenID
discovery document and the Contrix server description endpoint:

- `/.well-known/openid-configuration`
- `/api/v1/server/describe`

Run `coauth doctor` after the server is up to verify these discovery surfaces.
