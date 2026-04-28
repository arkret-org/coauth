# `manage`


The Pasion CLI provides several subcommands for managing users and configurations

Global options:
- `--config <config>`: Path to the configuration file.
- `--help`: Print help.

## `manage add-email`

Add an email address to the specified user.

```
$ coauth manage add-email <username> <email>
```

## `manage verify-email`

[DEPRECATED] Mark an email address as verified.

```
$ coauth manage verify-email <username> <email>
```

## `manage promote-admin`

Make a user admin.

```
$ coauth manage promote-admin <username>
```

**This doesn't make all the users sessions admin, but rather lets the user request admin access in administration tools.**

## `manage demote-admin`

Make a user non-admin.

```
$ coauth manage demote-admin <username>
```

## `manage list-admin-users`

List all users with admin privileges.

```
$ coauth manage list-admins
```

## `manage set-password`

Set a user password.

Options:
- `--ignore-complexity`: Don't enforce that the password provided is above the minimum configured complexity.

```
$ coauth manage set-password <username> <password> --ignore-complexity
```

## `manage issue-compatibility-token`

Issue a compatibility token for a user.

Options:
- `--device-id <device_id>`: Device ID to set in the token. If not specified, a random device ID will be generated.
- `--yes-i-want-to-grant-admin-privileges`: Whether the token should be given admin privileges.

```
$ coauth manage issue-compatibility-token <username> --device-id <device_id> --yes-i-want-to-grant-admin-privileges
```

## `manage issue-user-registration-token`

Create a new user registration token.

Options:
- `--token <token>`: Specific token string to use. If not provided, a random token will be generated.
- `--usage-limit <usage_limit>`: Limit the number of times the token can be used. If not provided, the token can be can be used only once, unless the `--unlimited` flag is set.
- `--unlimited` Allow the token to be used an unlimited number of times.
- `--expires-in <expires_in>`: Time in seconds after which the token expires. If not provided, the token never expires.

```
$ coauth manage issue-user-registration-token --token <token> --usage-limit <usage_limit> --expires-in <expires_in>
```

## `manage provision-all-users`

Trigger a provisioning job for all users.

```
$ coauth manage provision-all-users
```

## `manage kill-sessions`

Kill all sessions for a user.

Options:
- `--dry-run`: Do a dry run, ie see which sessions would be killed.

```
$ coauth manage kill-sessions <username> --dry-run
```

## `manage lock-user`

Lock a user.

Options:
- `--deactivate`: Whether to deactivate the user.

```
$ coauth manage lock-user <username> --deactivate
```

## `manage unlock-user`

Unlock a user.

Options:
- `--reactivate`: Whether to reactivate the user.

```
$ coauth manage unlock-user <username> --reactivate
```

## `manage register-user`

Register a user. This will interactively prompt for the user's attributes unless the `--yes` flag is set. It bypasses any policy check on the password, email, etc.

Options:
- `--username <username>`: Username to register.
- `--password <password>`: Password to set.
- `--email <email>`: Email to add. Can be specified multiple times.
- `--upstream-provider-mapping <UPSTREAM_PROVIDER_ID:SUBJECT>`: Upstream OAuth 2.0 provider mapping. Can be specified multiple times.
- `--admin`: Make the user an admin.
- `--no-admin`: Make the user not an admin.
- `--yes`: Don't ask questions, just do it.
- `--display-name <display_name>`: Set the user's display name.
- `--ignore-password-complexity`: Don't enforce that the password provided is above the minimum configured complexity.

```
$ coauth manage register-user
```
