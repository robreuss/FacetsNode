# Spaces Sync participant sponsorship

Implemented protocol contract, September 13, 2026. Native acceptance is a
separate client gate; this document does not claim all-devices-lost recovery.

- Space admission requires current device-bound control and Space credentials
  plus the Space administration bearer. The service resolves memberships from
  its own principal/Space bindings and verifies capabilities, expiry, scope,
  current subscription and credential digests. Caller IDs are not authority.
- The accepted record binds sponsor control/Space and target control
  subscription incarnations and credential digests. Raw member bearer tokens
  are transient HTTPS request fields, never stored in that record.
- Claim rechecks current memberships and the binding. Rotated sponsor
  credentials make an unclaimed grant superseded. Already-claimed exact retries
  do not depend on the former sponsor remaining online or enrolled, but still
  authenticate the exact target claim and its current subscription.
- One unclaimed attempt owns a target for two minutes of server time. A fresh
  eligible sponsor can then atomically revoke its unclaimed reservation and
  replace it. Old admission/subscription evidence prevents resurrection.
  Original-device readmission follows the same inactive-membership rules.
- Cancellation uses the scoped `device-admissions/{admissionID}/cancellation`
  endpoint with version, retry ID, target ID and sponsor credentials. It
  durably fences even a prepare request that has not arrived. An exact claimed
  attempt returns `cancelled: false` and is never revoked. Another sponsor
  cannot cancel an owned attempt. Claim/cancel serialize in one SQL transaction.
- The generic relay member/admission create and claim routes reject Spaces
  Sync service deployments so they cannot bypass this protocol. Other relay
  services and ordinary data/rebootstrap operations keep their existing scope.
- Cancellation fences and sponsor bindings are included in service-state
  export/import. This is portable Box state, not an old-schema compatibility
  migration. Existing development databases are not upgraded or patched; use
  the explicit fresh isolated acceptance deployment workflow.

Verification: memory store/authentication tests, HTTP boundary and mutation
fence tests, complete Go race suite, and PostgreSQL readmission, takeover,
cancel-before-prepare/reopen and concurrent claim/cancel tests. The latter use
a dedicated disposable PostgreSQL container/database, not existing Box data.
No changes to root recovery authority, content encryption or automatic
checkpoint collection are included.
