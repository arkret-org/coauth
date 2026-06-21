# Principal Server configuration

coauth now runs as the Cokret Auth Server. Downstream Principal Servers such as
Soland consume OAuth/OIDC tokens and Cokret session grants; coauth no longer
connects to the retired delegated-auth adapter.

## Configure Soland as a Principal Server

Declare each trusted Principal Server in the `cokret.principal_servers`
section:

```yaml
cokret:
  principal_servers:
    - name: soland
      audience: did:webvh:<scid>:soland.example.com:webvh:service
      endpoint: https://soland.example.com/
      did: did:webvh:<scid>:soland.example.com:webvh:service
```

- `name`: operator-facing identifier for the Principal Server.
- `audience`: service DID audience expected by that server.
- `endpoint`: base URL advertised through Cokret/OIDC discovery.
- `did`: optional DID advertised for the Principal Server.

## Discovery

coauth publishes Principal Server metadata through the standard OpenID
discovery document and the Cokret server description endpoint:

- `/.well-known/openid-configuration`
- `/_cokret/describe`

Run `coauth doctor` after the server is up to verify these discovery surfaces.
