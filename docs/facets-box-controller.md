# Facets Box controller

The controller is the content-blind control plane behind one public Box URL,
for example `https://box.example/facetsbox`. It owns the Box identity, Box
Owner authentication, Web sessions, app-connection grants, service catalog,
and redacted activity log. It does not receive a Device Sync database
credential, deployment signing key, content key, backup-decryption authority,
Docker socket, or generic service-command capability.

Device Sync is registered beneath the same URL at
`/facetsbox/device-sync`. The controller reaches two private Device Sync
operations on an internal Docker network: list published Sync Group profiles
and issue one one-time account admission. Device Sync signs that admission
itself. The public signed Box manifest contains service kinds and endpoints but
never group names; a scoped app-connection grant is required for the profile
that includes groups.

## First initialization

1. Configure independent random values for
   `FACETS_BOX_CONTROLLER_POSTGRES_PASSWORD` and
   `FACETS_DEVICE_SYNC_BOX_CONTROLLER_TOKEN`.
2. Configure `FACETS_BOX_PUBLIC_URL` and `FACETS_BOX_DEVICE_SYNC_URL` with the
   single public base and Device Sync subpath.
3. Start both PostgreSQL services, then run the controller image once with the
   `initialize` command. It creates a distinct Ed25519 Box identity and prints
   a single activation code. Only an Argon2id verifier is retained.
4. Start the full Compose project. The first Box Web session presents the
   activation code and a new 15–128 character Box Owner password. Successful
   claim consumes the activation verifier.

The Box Owner password is normalized Unicode and accepts spaces and password
manager paste. There are no composition rules or periodic expiry. Common
choices are rejected. Only a versioned Argon2id verifier is stored. Repeated
login failures are throttled. Web sessions use Secure, HttpOnly, SameSite
cookies plus CSRF tokens and bounded idle/absolute lifetimes.

## App connection

Facets creates a short-lived request with an ephemeral X25519 key and opens the
approval page inside its pinned Box Web view. Claim or Box Owner login approves
the request. The controller returns the connection grant and optional first
Device Sync admission only through a ChaCha20-Poly1305 envelope bound to that
request. Neither value appears in the URL, clipboard, Web history, or audit
log. The app stores the connection grant in platform-protected storage and
uses it only for service and Sync Group discovery.

Changing the Box Owner password atomically revokes all Web sessions and app
connection grants. It does not alter Device Sync principal membership. Trusted
device removal remains a root-authorized Device Sync action inside Facets.
