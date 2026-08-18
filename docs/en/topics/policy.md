# Policy engine

A set of actions are controlled by a generic policy engine.
A decision of the policy engine is deterministically made based on three components:

 - The policy itself
 - A static configuration
 - The action to be performed

coauth evaluates policy through an abstraction layer with a single shipped backend:

| Backend | Language | Performance | Flexibility | Feature Flag |
|---------|----------|-------------|-------------|--------------|
| **Cedar** (default) | Cedar | Excellent (native Rust) | Medium | `cedar` |

## Cedar backend (default)

[Amazon Cedar](https://www.cedarpolicy.com/) is a policy language designed for simplicity and performance. Since Cedar is natively written in Rust, it integrates directly into coauth with no WebAssembly overhead.

Cedar is a good choice when:
- You want a simple, readable policy language
- You prefer a purely declarative approach to authorization

### Configuration

```yaml
policy:
  engine: cedar
  cedar_policy_file: ./policies/cedar/default.cedar
```

### Writing Cedar policies

Cedar evaluates authorization requests of the form `(principal, action, resource, context)`. coauth maps policy evaluations as:

- **Principal**: `Requester::"anonymous"`
- **Action**: `Action::"register"`, `Action::"add_email"`, `Action::"register_client"`, `Action::"authorize"`
- **Resource**: `Resource::"default"`
- **Context**: The evaluation input data (username, email, client metadata, etc.)

Example Cedar policy file:

```cedar
// Allow all registrations by default (Cedar defaults to deny)
permit(
    principal,
    action == Action::"register",
    resource
);

// Block registration with short usernames
forbid(
    principal,
    action == Action::"register",
    resource
) when {
    context.username.size() < 3
};

// Allow all email additions
permit(
    principal,
    action == Action::"add_email",
    resource
);

// Allow all client registrations
permit(
    principal,
    action == Action::"register_client",
    resource
);

// Allow all authorization grants
permit(
    principal,
    action == Action::"authorize",
    resource
);
```

## Custom backend

You can implement your own policy backend by implementing the `PolicyProviderFactory` and `PolicyEvaluator` traits from `coauth-policy`, and constructing a `PolicyFactory` via `PolicyFactory::from_provider()`.

## Actions

The policy engine mainly restricts three operations:

 - **User attributes**, which includes user registration, user profile updates, and user password changes.
 - **Client registration**, when an OAuth dynamic client registration is requested.
 - **Authorization requests**, when a client requests an access token.

Policies are only evaluated in user-facing contexts, and not in administrative contexts.
As such, they usually can be bypassed through the admin API or the CLI if needed.

### User attributes

The policy is evaluated in the following different scenarios:

 - During user registration, either with password credentials or with an upstream OAuth provider. This calls the email policy as well.
 - When a user adds a new email address to their account.

### Client registration

The policy is evaluated when a client sends their metadata through the OAuth dynamic client registration API.
By default, it enforces a set of strict rules to make sure clients provide enough information about themselves, with coherent URLs.
This is useful in production environments, but can be relaxed in development environments.

### Authorization requests

The policy is evaluated when a client requests an access token.
This covers OAuth sessions.
It is evaluated for the authorization code grant, the client credentials grant and the device authorization grant.

This is probably the most interesting policy, as it defines which scope can be granted to which user and which client.

On evaluation, three main entities are available:

 - details about **the grant**, such as the type of grant and the requested scopes
 - **the client** making the request
 - **the user** with their attributes (only for the authorization code grant and the device authorization grant)

The policy evaluation cannot *modify* the grant, only allow or deny it.
Therefore the client must know in advance which scope they want to request.

This is an important concept to understand: what access a token has is stored in the session itself, therefore access to privileged scopes is only based on policy evaluation, not on user attributes.

If we take coauth admin API access as an example, the fact that an access token has admin API access doesn't depend on attributes on the user *directly*.
Instead, it is during the creation of the session that:

 - the client asks for the corresponding scope (e.g. `urn:coauth:admin`)
 - the policy engine decides whether to grant it or not

The default policy shipped with the service does gate access to this scope based on a user attributes (`can_request_admin`), but this is not a requirement.

It does make reasoning about admin access more explicit than a simple boolean flag on the user, but it also allows for more complex authorization logic.
This is especially important as in the future it will make it possible to implement a more granular role-based access control system to fit more complex use cases.

To understand the authorization process and how sessions are created, refer to the [authorization and sessions](./authorization.md) section.


