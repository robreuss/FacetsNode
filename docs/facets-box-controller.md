# Facets Box controller

The controller is the content-blind control plane behind one public Box URL,
for example `https://box.example/facetsbox`. It owns the Box identity, Box
Owner authentication, Web sessions, app-connection grants, service catalog,
and redacted activity log. It does not receive a Device Sync database
credential, deployment signing key, content key, backup-decryption authority,
Docker socket, or generic service-command capability.

Device Sync is registered beneath the same URL at
`/facetsbox/device-sync`, but Device Sync membership is not part of Box claim or
Box membership. A Box member may discover Sync Groups and ask the Device Sync
service to issue a one-time bootstrap for a new, isolated group. The controller
uses one narrowly scoped private capability for those two operations; Device
Sync still signs the admission and the controller receives no signing key or
authority to add a device to an existing group. The public signed
Box manifest contains only the Box identity, claimed state, display name, and
service kinds/endpoints. A scoped member grant is required for the authenticated
service-status and Sync Group profile.

## First initialization

1. Configure an independent random value for
   `FACETS_BOX_CONTROLLER_POSTGRES_PASSWORD`.
2. Configure `FACETS_BOX_PUBLIC_URL` and `FACETS_BOX_DEVICE_SYNC_URL` with the
   single public base and Device Sync subpath.
3. Start both PostgreSQL services, then run the controller image once with the
   `initialize` command. It creates a distinct Ed25519 Box identity and prints
   a single activation code. Only an Argon2id verifier is retained.
4. Start the full Compose project. The first Box Web session presents the
   activation code, a Box display name, and a new 15–128 character Box Owner
   password. Successful claim consumes the activation verifier and opens the
   complete management dashboard. Claim creates no app grant or Device Sync
   group.

The Box Owner password is normalized Unicode and accepts spaces and password
manager paste. There are no composition rules or periodic expiry. Common
choices are rejected. Only a versioned Argon2id verifier is stored. Repeated
login failures are throttled. Web sessions use Secure, HttpOnly, SameSite
cookies plus CSRF tokens and a 30-minute idle limit. Authenticated administration
renews the 12-hour cookie/storage window; it has no absolute cutoff during active
configuration. Renewal does not recreate expired, revoked, or signed-out sessions.
The Desktop host maintains this activity only while its administration panel is
foregrounded, using a pinned read-only home request without navigating the form.
Client grants and sync service operation are independent of owner-session expiry.

## App connection

For an additional installation, a signed-in Box Owner displays a single-use
six-digit code in the Box dashboard and enters it in Facets. The controller
returns a connection grant through the encrypted response bound to that exact
request. Initial Box claim has a separate one-time activation-code flow. The
app stores its connection grant in platform-protected storage and uses it for
generic authenticated service discovery. The grant cannot administer the Box
or enroll the installation in any service by itself.

The separate Box-participant proof path has a durable one-use challenge
primitive. A challenge is bound to one claimed Box, participant, and device,
expires within two minutes, and is atomically consumed once. Issuance and
consumption now require the same pinned, active signed device grant. Revoking
the Box-local participant or its exact device grant blocks both new and
outstanding challenges. The Box Owner can invoke the revocation control with
an authenticated Web session and CSRF token; an ordinary app-connection grant
cannot do so. The owner dashboard now lists pinned participant/device IDs,
their self-asserted signed device name, and the separate revocation controls.
No canonical Persona identity is inferred from this display. Revocation is a
cutoff at this Box, not a claim to revoke the Principal's private root or its
participation elsewhere.

The internal store validates and pins an owner-approved Box-scoped public root
with its first exact signed device grant. It rejects changed retries and
duplicate scoped identities or device keys. The Box stores only public
authority records, not the private Principal root or device keys. The proof
verifier now requires a stored pin and rejects caller-supplied authority that
differs from it before consuming the challenge. A connected installation can
submit a signed, time-limited participant request at
`POST /v1/participant-enrollment-requests` and poll its decision at
`GET /v1/participant-enrollment-requests/{requestID}`. The Box Owner sees the
requesting installation and self-presented name, then explicitly approves or
rejects it in the dashboard. Approval atomically pins the exact signed root
and device; connecting with the six-digit code alone still grants discovery
only. The request ID is also the signed proof challenge ID, so changing it
cannot replay a proof under a new request. The proof also signs a digest of the
Box-local presented name and revision, so a connection grant cannot relabel
another device's signed request. The requesting app's connection
grant must remain active through approval. Requests expire after 30 minutes.

Facets now submits and polls the owner-approved participant request. The
controller also exposes an authenticated, durable one-use participant challenge
and a first shared-Worker directory. An active enrolled participant can publish
or withdraw one exact Worker advertisement by signing the canonical operation
and capabilities digest with its pinned device key. The Box rejects action or
payload substitution, replay, owner/device changes, stale revisions, expiry,
and revoked participant authority. Connected installations may list only
current advertisements. The capabilities payload is bounded opaque data: the
Box carries it but does not become a model-runtime authority.

**Directory listing is not permission to execute work.** The six-character
owner-confirmed Worker access request/grant, encrypted Job carriage, Worker
claim, cancellation, and durable Principal-signed revocation feed remain
absent. No shared Job route is enabled by the directory. Memory store and HTTP
tests pass; PostgreSQL integration tests require
`FACETS_BOX_TEST_DATABASE_URL` to execute against a live test database.

## Nearby discovery and multiple Boxes

The separate `facets-box-discovery` sidecar verifies the controller's signed
public manifest and advertises `_facets-box._tcp` over Bonjour. Its bounded TXT
record contains protocol version, Box ID, display name, public HTTPS URL,
identity-key fingerprint, claimed state, and service kinds. It receives no Box
database credential, owner session, member grant, or service-private state.

Clients key saved Boxes and protected grants by Box ID. The URL is a locator,
not identity: a changed identity at a known locator is rejected. Multiple Boxes
may share a display name and remain distinguishable by location and identity
suffix. Manual HTTPS URL entry remains the hosted/remote fallback.

Changing the Box Owner password atomically revokes all Web sessions and app
connection grants. It does not alter Device Sync principal membership. Trusted
device removal remains a root-authorized Device Sync action inside Facets.
