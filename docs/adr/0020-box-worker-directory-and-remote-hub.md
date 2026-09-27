# ADR 0020: Box Worker directory and exact remote Worker routing

**Status:** Accepted product direction for unreleased development; no new
participant, directory, grant, or Job route implemented by this ADR

**Date:** 2026-09-27

## Context

Facets selects specific Workers for a Job. A household Box should let enrolled
participants discover and request access to another participant's explicitly
shared Worker without making every device pair separately with every other
device. A remote Worker Hub may later perform analogous discovery and routing
over the Internet. The Hub is not automatically a Pool choosing a substitute
Worker, and a remote Job does not detour through the source's local Box.

The current Box connection grant permits service discovery, not Box
administration or membership in any service. Compute Pool has independent
authority and exact signed admission contracts, but its HTTP service does not
yet route Jobs. Neither existing surface can be treated as a Worker-sharing
grant merely by changing the UI.

## Decision

1. Add separately authenticated Box participant/device enrollment. The
   participant authority is Principal-backed and can cover that participant's
   authorized Box-enrolled devices. A Persona is a displayed identity
   projection, not the credential or authorization subject. Box
   administration, service discovery, participation, and Worker-use grants
   remain distinct scopes.
2. A Worker owner explicitly advertises a specific Worker for sharing.
   Listing reveals only the metadata needed for discovery, status, capability
   matching, and consent. The Box does not infer an offer from the presence of
   a client, a Worker process, or a connection grant.
3. A participant selects one Worker and requests a grant. The requesting
   client displays a fresh, short-lived six-character code. Entering that code
   on the owner's Worker device approves that named participant for that
   Worker and requested scope. The approval protocol must bind exact Box,
   participant, owner, Worker, attempt, and expiry and reject replay or
   exhausted attempts. The code is not a persistent bearer token. Production
   implementation requires an explicit authentication and abuse review.
4. The owner may pause sharing, revoke one participant, or stop an active Job.
   These remove future admission immediately. An in-flight stop remains
   requested until confirmed by the executor or resolved by lease expiry;
   the Box cannot assert that a process stopped merely because it forwarded
   a control message.
5. The source-signed Job assignment names a fixed set of authorized Workers.
   The Box/Hub verifies admission for the exact selected Worker and does not
   substitute a different one. Capacity, capability, grant, offering revision,
   recipient key, and lease constraints remain in force. Optional Pool
   “choose for me” placement requires a separate source choice; it is not the
   default behavior of a Worker directory.
6. The Box and Hub carry protected Job bytes without plaintext content
   authority. Transport custody, Worker execution, and source application are
   separate facts with separate receipts. Disconnected or offline Workers
   produce waiting/needs-attention state, not an implicit replacement.
7. A remote Hub is a distinct reachable directory/forwarder for Workers
   advertised there. A Facets source goes to that Hub directly. Its invitation
   and grant flow should share vocabulary with local Box sharing but use an
   Internet-appropriate authority and recovery review before enablement.

## Relationship to earlier decisions

ADR 0004's independent Compute Pool authority and ADR 0005's exact Worker and
offering admission still apply. Their Pool scheduling language does not grant
the Pool permission to override a source's fixed assigned set. If a person
explicitly selects Pool placement, the resulting candidate set and selection
policy must be separately authorized and visible.

This decision does not turn Box participation into Shared Space membership,
Box owner status, payment authority, or access to another participant's
Space. A Worker sees only an authorized bounded Job input. Persona recovery
and presentation are client concerns; the Box needs minimal authenticated
participant labels and revocation state, not the user's Persona library.

## Current implementation and acceptance boundary

This ADR changes no runtime behavior. The existing `boxcontrol.ConnectionGrant`
remains a discovery credential. The current Compute Pool HTTP surface remains
status/deployment-oriented. Live acceptance requires contract fixtures,
enrollment and revocation tests, a Worker directory, a grant ceremony, exact
admission, encrypted carriage, distinct receipts, restart recovery, owner
stop, and actual-device demonstrations. A loopback or schema test is not
evidence of a working shared Worker.
