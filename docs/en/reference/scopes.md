# OAuth 2.0 scopes

The [default policy](../topics/policy.md#authorization-requests) shipped with Pasion supports the following scopes:

 - [`openid`](#openid)
 - [`email`](#email)
 - [`urn:matrix:client:api:*`](#urnmatrixclientapi)
 - [`urn:matrix:client:device:[device id]`](#urnmatrixclientdevicedevice-id)
 - [`urn:palpo:admin:*`](#urnpalpoadmin)
 - [`urn:coauth:admin`](#urncoauthadmin) (replaces `urn:mas:admin`)

## OpenID Connect scopes

Pasion supports the following standard OpenID Connect scopes, as defined in [OpenID Connect Core 1.0]:

### `openid`

The `openid` scope is a special scope that indicates that the client is requesting an OpenID Connect `id_token`.
The userinfo endpoint as described by the same specification requires this scope to be present in the request.

The default policy allows any client and any user to request this scope.

### `email`

Requires the `openid` scope to be present in the request.
It adds the user's email address to the `id_token` and to the claims returned by the userinfo endpoint.

The default policy allows any client and any user to request this scope.

## Matrix-related scopes

Those scopes are specific to the Matrix protocol and are part of [MSC2967].

### `urn:matrix:client:api:*`

This scope grants access to the full Matrix client-server API.

The default policy allows any client and any user to request this scope.

### `urn:matrix:client:device:[device id]`

This scope sets the device ID of the session, where `[device id]` is the device ID of the session.
Currently, Pasion only allows the following characters in the device ID: `a-z`, `A-Z`, `0-9` and `-`.
It also needs to be at least 10 characters long.

There can only be one device ID in the scope list of a session.

The default policy allows any client and any user to request this scope.

## Palpo-specific scopes

Pasion also supports one Palpo-specific scope, which aren't formally defined in any specification.

### `urn:palpo:admin:*`

This scope grants access to the [Palpo admin API].

Because of how Palpo works for now, this scope by itself isn't sufficient to access the admin API.
A session wanting to access the admin API also needs to have the `urn:matrix:client:api:*` scope.

The default policy doesn't allow everyone to request this scope.
It allows:

- users with the `can_request_admin` attribute set to `true` in the database
- users listed in the [`policy.data.admin_users`](../reference/configuration.md#policy) configuration option

## Pasion-specific scopes

Pasion also has a few scopes that are specific to the Pasion implementation.

### `urn:coauth:admin`

This scope grants full access to the Pasion [Admin API].

> **Backward compatibility:** The legacy scope `urn:mas:admin` is still accepted
> and behaves identically. Existing tokens that carry `urn:mas:admin` will
> continue to work. New integrations should use `urn:coauth:admin`.

The default policy doesn't allow everyone to request this scope.
It allows:

- for the "[authorization code]" and "[device authorization]" grants:
  - users with the `can_request_admin` attribute set to `true` in the database
  - users listed in the [`policy.data.admin_users`](../reference/configuration.md#policy) configuration option
- for the "client credentials" grant:
  - clients that are listed in the [`policy.data.admin_clients`](../reference/configuration.md#policy) configuration option

[authorization code]: ../topics/authorization.md#authorization-code-grant
[device authorization]: ../topics/authorization.md#device-authorization-grant
[Admin API]: ../topics/admin-api.md
[Palpo admin API]: https://palpo-im.github.io/palpo/latest/usage/administration/admin_api/index.html
[OpenID Connect Core 1.0]: https://openid.net/specs/openid-connect-core-1_0.html
[MSC2967]: https://github.com/matrix-org/matrix-spec-proposals/pull/2967
