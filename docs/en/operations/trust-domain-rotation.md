# Trust domain rotation

`arkret.trust_domain` binds peer and recovery authorization transcripts
to a deployment. Changing it invalidates in-flight proofs and sessions
issued under the previous trust domain.

Before rotating:

1. Record the current configured value and confirm it matches
   `/_arkret/describe`.
2. Pause or reject in-flight recovery approvals minted under the old value.
3. Snapshot the database and keep the previous config alongside the
   snapshot.
4. Coordinate with Principal Server operators so they reject stale
   recovery proofs after the cutover.

During rotation:

1. Set the new value in `arkret.trust_domain`.
2. Restart one `coauth` replica and verify `/_arkret/describe`
   advertises the new value.
3. Roll the remaining replicas.
4. Reissue reset proofs through the device recovery strand. The affected
   proof families are `principal_signing`, `recovery_unlock`,
   `device_quorum`, and `trusted_recovery_service`.
5. Complete the root-anchored device re-anchor after the new proofs are
   available.

Do not replay old reset proofs into the new trust domain. They must fail
because their canonical transcript was signed for a different
deployment scope.
