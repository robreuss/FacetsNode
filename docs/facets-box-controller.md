# Facets Box controller

The controller is the content-blind control plane behind one public Box URL,
for example `https://box.example/facetsbox`. It owns the Box identity, Box
Owner authentication, Web sessions, app-connection grants, service catalog,
and redacted activity log. It does not receive a Device Sync database
credential, deployment signing key, content key, backup-decryption authority,
Docker socket, or generic service-command capability.

Device Sync is registered beneath the same URL at
`/facetsbox/device-sync`, but Device Sync membership is not part of Box claim or
Box membership. The controller can health-check the private service endpoint;
it holds no Device Sync signing key or membership authority. The public signed
Box manifest contains only the Box identity, claimed state, display name, and
service kinds/endpoints. A scoped member grant is required for the authenticated
service-status profile.

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
cookies plus CSRF tokens and bounded idle/absolute lifetimes.

## App connection

Facets creates a ten-minute request with an ephemeral X25519 key and displays a
single-use six-digit code. A signed-in Box Owner enters that code in the Box
dashboard. Codes are unique among active requests, throttled on failure, and
never appear in URLs, clipboard data, Web history, or logs. The controller
returns a member grant only through a ChaCha20-Poly1305 envelope bound to the
exact request. The app stores the device-bound grant in platform-protected
storage and uses it only for the generic authenticated service profile. The
grant cannot administer the Box or enroll the installation in any service.

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
