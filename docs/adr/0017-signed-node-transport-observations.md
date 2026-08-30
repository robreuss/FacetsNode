# ADR 0017: Signed recipient-bound Node transport observations

Status: Accepted for the portable contract checkpoint, 2026-08-30

## Context

Facets Sentry needs trustworthy provenance when it later consumes facts that
only FacetsNode can authoritatively observe: replayed envelopes, cursor
rollback, delivery gaps, opaque blob mismatches, routing-lease conflicts,
quota anomalies, protocol-version misuse, and service health. FacetsNode must
remain content-blind and must not become a semantic Space authority, a Space
opener, a Sentry, a quarantine authority, or a remote actuator.

The existing `relay_audit_events.event_sequence` is a deployment-local audit
row sequence. It is not a stable portable event identity and cannot be
retrofitted after the fact into a signed recipient record. The existing local
Facets `SecurityObservation` and `SecurityEvidenceReceipt` also cannot
represent a Node fact honestly: they require device-local Space/runtime and
local evidence-custody provenance that FacetsNode neither knows nor controls.

## Decision

Define `NodeTransportObservation` as a new portable contract in
`internal/serviceauthority`. It is not yet connected to a database, API,
delivery route, client inbox, Sentry store, finding, decision, action, receipt,
or Backup service.

### Source transaction and stream identity

A production source transaction must atomically persist one stable
`observationID` with the exact Node fact. The signed payload also carries a
deployment-scoped `streamID`, positive `sequence`, and predecessor reference.
Sequence one has no predecessor; every later sequence has exactly one. A
successor must retain the exact authenticated service scope, deployment,
deployment signing key, and stream, increment sequence by exactly one, and
name the exact predecessor signed-record reference digest.

The authority revision and manifest digest may advance within a stream while
the same service scope, deployment, and key remain active. Every record must be
authorized independently against its exact historical manifest. Timestamps
are descriptive only and are never causal order. A decoded record by itself
does not prove a complete stream. A valid successor chain does not prove that
the deployment did not fork or withhold another chain.

The domains are distinct:

```text
Facets Node transport observation v1\0
Facets Node transport observation reference v1\0
Facets Node protected observation envelope reference v1\0
Facets Node recipient principal device grant record reference v1\0
```

The canonical signed payload is at most 64 KiB. The signature is the existing
canonical low-S raw ES256 form. The signed-record reference digest covers the
signature as well as the payload. Therefore an exact retry reuses the original
signed bytes and reference. Regenerating ES256 for the same payload is a new
record representation, not an exact retry; reusing one observation identity
with different bytes must later fail closed in recipient persistence.

### Authenticated authority and implementation provenance

Recipient-visible v1 observations always carry a complete authenticated
service-authority context:

- exact `FacetsServiceScope` kind and ID;
- positive authority revision and exact manifest reference digest;
- deployment ID and deployment signing-key fingerprint inside signed bytes;
- implementation identifier;
- exact 40-character source revision and 64-character source-tree digest;
- service protocol identifier/version and observation protocol version.

`serviceKind` is the authenticated service scope kind (`device_sync`,
`shared_space`, or `compute_pool`), not an implementation label. Failed
authentication remains server-local operational telemetry. In particular, a
failed authentication attempt never produces a recipient-visible record keyed
by attacker-supplied tenant, Space, member, or service identities.

`VerifiedPayload` proves canonical structure and cryptographic integrity under
the public key embedded in the signature. It is deliberately not
authorization. `Authorize` separately requires an independently trusted
authority manifest and trust anchor and matches the exact scope, revision,
manifest digest, active deployment, signing key, and the manifest validity
window at the record's commit time. Trusting the embedded key would let the
Node authorize itself.

Historical verification is a client-intake prerequisite. The current client
trust store retains only the latest manifest snapshot. A recipient inbox must
retain authenticated manifest/deployment-key history or validate a complete
authority-authorized history chain before it can admit old records. Neither
falling back to the current deployment key nor accepting an embedded historical
key is permitted.

### Recipient-protected delivery binding

The signed `deliveryProtection` binds all of:

- exact delivery recipient device ID;
- exact recipient agreement/encryption-key fingerprint;
- closed `P256-HKDF-SHA256+A256GCM` suite identifier;
- one exact closed recipient-authority record reference;
- reference digest and byte count of the complete canonical protected
  observation envelope.

The protected-envelope reference covers its exact canonical bytes, including
ephemeral agreement key, nonce, authentication tag, and ciphertext. The
protected envelope is capped at 128 KiB. This checkpoint does not implement
encryption or decryptability. `ValidateRecipientBinding` only compares the
signed binding, including the complete authority reference, with values
independently known by the caller. Service-authority validation cannot
authorize a recipient key, and the authority reference only identifies the
historical record that a later verifier must consult.

The recipient-authority union is exact:

- `device_sync` requires `device_sync_principal_grant`, carrying positive
  `deviceGeneration`, exact grant UUID, and the reference digest of the exact
  canonical full signed principal-device-grant record (payload plus signature);
- `shared_space` requires `shared_space_roster`, carrying exact participant
  UUID, positive roster revision, and the existing full signed roster
  attestation digest;
- `compute_pool` is rejected in v1.

The Device Sync grant-record reference helper domain-separates and hashes at
most 64 KiB of caller-supplied exact canonical full-record bytes. It does not
decode, verify, or authorize those bytes. A signature mutation therefore
changes the reference, but possession of matching bytes remains only an input
to later historical authority evaluation.

Future Device Sync intake must match the exact service-scope principal, grant
ID, recipient device ID, device generation, agreement-key fingerprint, and
full signed-grant digest, then evaluate the complete authenticated root,
grant, supersession, expiry/not-before, capability, and revocation set at the
observation's commit time. In particular, any required receive capability is
an intake decision, not a claim made by this reference.

Future Shared Space intake must resolve the exact independently accepted
roster authority chain and match the referenced roster revision, full signed
attestation digest, participant ID, recipient device ID, and agreement-key
fingerprint. Shared Space has no authenticated device-key epoch today, so v1
does not invent one. If the roster later defines such a generation, portable
observations require a new schema version rather than reinterpreting this
record.

A Device Sync or Shared Space relay envelope referenced by a fact uses its own
complete canonical `relay_envelope` reference digest. It is not the protected
observation-envelope digest and must never be replaced by a bare relay row ID.

### Closed content-blind fact vocabulary

Fact references are discriminated and bounded. UUID references use only
`identifier`; signed-record/blob references use only `referenceDigest`; service
components use only a bounded canonical machine identifier. Measurements are
closed discriminated structures rather than maps or generic values. Optional
evidence has a closed kind, exact reference digest, positive bounded byte
count, and at most eight entries. References and evidence are canonically
sorted and deduplicated.

The v1 matrix is exact:

| Fact | References | Measurement | Allowed evidence |
| --- | --- | --- | --- |
| `invalid_envelope` | one `relay_envelope` digest | none | `transport_record` |
| `replayed_envelope` | one `relay_envelope` digest | none | `transport_record` |
| `cursor_rollback` | one subscription UUID | expected/observed sequence, observed lower | `transport_record` |
| `delivery_gap` | one subscription UUID | expected/observed sequence, observed higher | `transport_record` |
| `blob_digest_mismatch` | one blob reference digest | unequal expected/observed digest | `transport_record` |
| `routing_lease_conflict` | ordered lease and message UUIDs | none | `transport_record` |
| `quota_rate_anomaly` | exactly one subscription, member, or replica UUID | observed count above limit and positive window | `transport_record` |
| `unexpected_protocol_version` | one service component | observed version and supported maximum, unequal | `protocol_record` |
| `service_health_degraded` | one service component | none | `service_health_record` |

Paths, filenames, URLs, content, prompts, arbitrary error strings, local Space
instance IDs, client runtime generations, credentials, and semantic corpus
facts are not representable by this contract.

## Claims deliberately not made

A valid deployment signature proves only that the named deployment signed
those exact bytes. It does not prove that:

- the fact is true, complete, fresh, or non-equivocated;
- the referenced protected envelope is decryptable or was delivered;
- the referenced recipient authority record is authentic, current, unrevoked,
  capability-bearing, or authorized for the recipient;
- FacetsNode durably accepted or retained any other bytes;
- a recipient durably accepted, decrypted, applied, or agreed with the fact;
- a local Space is compromised, safe, quarantined, backed up, or restorable;
- any local Sentry finding or containment action is warranted.

Node custody, Node delivery, recipient durable acceptance, recipient
application/disposition, and local Sentry evidence custody remain distinct
future receipt claims. This contract defines none of them.

## Portable parity and next stages

The Go contract is mirrored in Swift under FacetsFEF, which already owns the
portable service-authority and signature vocabulary. FacetsNodeClient may
depend on it; FacetsSecurityCore must not become a dependency of this portable
transport contract.

A byte-identical Go/Swift golden fixture freezes the agreed wire names,
canonical bytes, signature, protected-envelope binding, exact signed Device
Sync grant-record reference, and observation reference digest.
Subsequent, separately reviewed work may add:

1. a recipient-owned foreign-observation inbox with replay/conflict handling,
   historical authority lookup, durable acceptance, and separate application
   disposition;
2. app transport injection and optional exact unique local binding;
3. a separate typed foreign-evidence link if local Sentry incidents ever need
   to reference an accepted Node record.

No intake stage may relabel Node provenance as local authority provenance,
decrypt inside Sentry, or turn a signature failure or Node-authored fact into a
finding or action.
