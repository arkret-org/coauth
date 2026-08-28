# Handle-claim ledger (issuer-internal)

coauth is a **handle-claim issuer**, not a handle **directory**. This page
records the R3.2 (arkret-spec @ `b56cab1`) scope decision for the
`ak.find.directory.read.list_handles_for_subject.v1` directory operation.

## Decision: coauth does NOT implement `ak.find.directory.read.list_handles_for_subject.v1`

R3.2 of the Arkret spec introduced
[`ak.find.directory.read.list_handles_for_subject.v1`][op] — given a known
holder/principal DID, return the current context-visible set of signed
`ak.schema.handle_claim.v1` evidence (the inverse of `resolve_handle`,
which maps a handle string to a subject).

**`ak.find.directory.read.list_handles_for_subject.v1` is a directory-service
operation.** In a standard Arkret deployment that role is carried by the
directory service (teabay), which applies disclosure policy, issuer-trust
filtering, audience scoping, and `as_of` historical replay across all
issuers visible in a Realm. coauth deliberately does **not** expose this
operation:

- coauth is authoritative only for the claims **it issues** for accounts
  in **this** organization. It has no cross-issuer / cross-organization
  view, so it cannot honour the operation's disclosure-policy and
  issuer-trust filtering contract for the general case.
- Exposing a subject -> handles lookup from the issuer would invite
  enumeration of an organization's membership and would duplicate (and
  risk diverging from) the directory service's authoritative filtering.

A consumer that needs `list_handles_for_subject` MUST call the directory
service (teabay), not coauth.

## What coauth provides instead

coauth retains an **issuer-internal ledger** of the handle claims it has
minted. The signed `ak.schema.handle_claim.v1` artefacts coauth produces
(see [`issue_handle_claim`][src] in `crates/backend/src/handlers/arkret/handle_claim.rs`)
are the only authoritative wire form for a handle; everything else
(roster hints, mention `handle_at_time`, etc.) is a derived projection or
audit metadata.

Per the R3.2 issuer hardening:

- coauth rejects `claim_type=service_handle` at issuance
  (reason `claim_type_unsupported`); only `handle_binding` /
  `organization_handle` are minted.
- coauth emits the subject as a canonical `DidCoreId` (`ak:did_core:...`).
  Principal role and authority are established by the audience-specific,
  registration-time binding; the core-id bytes alone do not prove a role.
  Retired role-prefixed ids and DIDs are rejected
  (reason `handle_claim_subject_not_principal_did`).

### Optional org-operator audit API

> **Status: not implemented (deferred).**
>
> An optional issuer-internal admin endpoint
> `GET /_coauth/admin/handles?subject=<did>` could let org operators audit
> which handles coauth currently holds for a subject **within this
> organization**. This is an issuer-side ledger view, explicitly **not**
> an implementation of `ak.find.directory.read.list_handles_for_subject.v1` and **not**
> a directory surface — it would carry no cross-issuer disclosure
> semantics. It is left as a `TODO(R3.2.1)` because the existing admin
> claims surface already covers operator audit needs; add it only if a
> concrete operator workflow requires it.

[op]: https://github.com/arkret-org/arkret-spec
[src]: ../../../crates/backend/src/handlers/arkret/handle_claim.rs
