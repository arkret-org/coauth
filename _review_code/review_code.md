# Regression Review

## 2026-08-01 — Agent session refresh incorrectly required a human browser/device session

- **Surface:** `POST /_arkret/gate/account/session-grants/refresh` for grants whose JWT
  `proof_kind` is `agent_key_proof`.
- **Regression:** the endpoint unconditionally required a browser session and validated refresh
  proof through the human device directory. Native Agents have neither, so a conforming Agent
  runtime could not rotate its short-lived grant and eventually stopped account/MLS maintenance.
- **Correction:** refresh now dispatches by the prior signed grant's proof kind. The Agent branch
  validates a fresh runtime-key proof, stable `device_id`, current Agent/controller lifecycle and
  exact active authorization, consumes the prior grant once, and mints an unbound successor with
  unchanged subject/scope/audience/DPoP binding and the independent Agent TTL cap.
- **Prevention dimension:** digest tests bind the prior grant, device, audience and authorization
  verification method; the backend target compiles the credential-specific branch and retains the
  existing negative test that `agent_key_proof` cannot enter the human soft-logout validator.
