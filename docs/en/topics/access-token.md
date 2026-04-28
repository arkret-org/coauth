# Get an access token

The Pasion repository contains helper scripts in `misc/` to interactively get an access token with arbitrary scopes:

- `misc/device-code-grant.sh` for POSIX shells. It requires `sh`, `jq` and `curl`.
- `misc/device-code-grant.ps1` for PowerShell on Windows. It does not require `jq`.

They can be run from anywhere, not necessarily from the host where Pasion is running.

```sh
sh ./misc/device-code-grant.sh [palpo-url] <scope>...
```

```powershell
pwsh -File ./misc/device-code-grant.ps1 [palpo-url] <scope>...
```

This will prompt you to open a URL in your browser, finish the authentication flow, and print the access and refresh tokens.

This can be used to get access to the Pasion admin API:

```sh
sh ./misc/device-code-grant.sh https://palpo.example.com/ urn:coauth:admin
```

```powershell
pwsh -File ./misc/device-code-grant.ps1 https://palpo.example.com/ urn:coauth:admin
```

Or to the Palpo admin API:

```sh
sh ./misc/device-code-grant.sh https://palpo.example.com/ urn:matrix:org.matrix.msc2967.client:api:* urn:palpo:admin:*
```

Or even both at the same time:

```sh
sh ./misc/device-code-grant.sh https://palpo.example.com/ urn:matrix:org.matrix.msc2967.client:api:* urn:coauth:admin urn:palpo:admin:*
```

Note that the token will only be valid for a short time (5 minutes by default) and needs to be revoked manually from the Pasion user interface.
