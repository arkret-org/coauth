# Agent Runtime Status

coauth exposes Agent key pairing and the Agent SessionGrant branch through
their canonical Arkret gate operations. Client entry points keep the
controller's sender-constrained session contract.

In a split deployment, the Account Authority delegates the Agent projection
read and exact pairing command to the explicitly configured owning Station.
That delegation uses an RFC 9421 service signature made with the owning
Station DID's authorised `#account-authority` assertion method. It binds the
method, exact target, operation, source and destination service ids, both trust
domains, and `Content-Digest` when a body is present. It never reuses the
session-grant introspection bearer.

The old product-private
`POST /_coauth/self/agents/{id}/accountability-grant` endpoint had no canonical
operation and no current caller, so it has been removed. Accountability facts
continue to travel through registered Events and Station projections.
