# Journey ownership and lifecycle

The mounted `/_coauth/self/journey` REST surface resolves six built-in plans.
Current first-party Coauth frontend, Codmin, Inkson and Garth sources do not call
these endpoints. Garth's `runtime_journey` is an independent Agent admission
model and is not a consumer of this Coauth engine. No standard Arkret v1 wire
operation defines these private Journey DTOs.

| Stage | Current executor effect | Authentication or durable write owner |
| --- | --- | --- |
| Identification | Collect `uid_field` and password-presence metadata; never retain the password | Account authentication service; requires verified credentials and real browser session |
| EmailVerification | Require a nonempty code; no verifier call | Account registration/recovery and email-auth services; rate-limited proof and durable completion |
| PasswordWrite | Require a new password and, if configured, current-password presence | Account password service; credential verification, hashing, session policy and transaction |
| UserWrite | Collect handle/display name in context | Account registration service; uniqueness, proof, authority/binding and final transaction |
| Consent | Select continue/done; no persisted consent | Owning OAuth/authorization service and its real transaction |
| CAPTCHA | Invoke the shared server-side verifier when supplied with configuration | `handlers/captcha.rs`; hostname/IP checks and fail-closed provider response; no built-in REST-resolved plan currently includes this stage |
| Prompt | Check required fields and collect prompt data | The product service that consumes that data; no write is wired here |
| EnrollmentToken | Check required token presence; no token-consumption call | Owning enrollment/registration service; real issuer validation and single use |

`JourneyDone` describes completion of this stage sequence. It does not prove a
user was authenticated, an email was verified, an account/password was written,
or a grant/consent was committed. The product integration gap belongs to the
existing 0931 business-scenario owner; recovery continuation belongs to 1638.

Sessions currently belong to one Coauth process. Restart loses them and different
instances cannot resume them. Persisting this context would not supply any of
the missing authentication or durable effects above. An eventual product caller
must first define those effects, their owning transaction and the replay/receipt
contract. This batch retains the reachable REST surface and its current plans;
it does not advertise durable or multi-instance continuation.

All statuses share the existing one-hour TTL and 50,000-entry bound. Global
locks only protect entry lookup/admission/capacity metadata. Each session has its
own mutex, held while a response runs, so concurrent responses observe the
previous committed stage while unrelated sessions can progress. External
CAPTCHA verification never holds a global map lock. Admission is rechecked after
waiting for the session and after external verification; expired, evicted or
replaced handles cannot update the session. A short map read guard protects the
synchronous commit from concurrent eviction. Cancelled verification leaves its
candidate context uncommitted and releases the session mutex.
