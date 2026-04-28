# About Application Services login

Encrypted Application Services/Bridges currently leverage the `m.login.application_service` login type to create devices for users.
This API is *not* available in the Pasion.

We're working on a solution to support this use case, but in the meantime, this means **encrypted bridges will not work with the Pasion.**

## Workarounds

- **Disable E2EE in bridges** — If your bridge does not require end-to-end encryption, configure it to skip device creation and key management.
- **Use unencrypted rooms** — Bridges can still operate on unencrypted rooms without needing the Application Service login API.

## Background

The `m.login.application_service` login type allows bridges to authenticate as any user and create devices on their behalf. This is necessary for encrypted bridges to manage encryption keys.

In a native OIDC deployment with Pasion, this login flow is not supported because authentication is handled entirely through OAuth 2.0 flows rather than the legacy Matrix login API.

## Future plans

Support for Application Service device management in an OIDC-native way is being tracked upstream in the Matrix specification process. Once a standard mechanism is defined, Pasion will implement it.
