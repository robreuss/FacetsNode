# Security policy

Facets Node carries high-value encrypted state and authorization capabilities.
Please do not disclose a suspected vulnerability in a public issue. Until a
dedicated security address is published, contact the project owner privately
through the repository hosting account.

The Node is an opaque transport, not a key server. Clients encrypt replica
messages with a separate domain content key. The operator, domain
tenant provisioning, domain administration, member admission, and member
bearer credentials authorize distinct routing operations and must never be
reused as content-encryption keys. The Node stores only their domain-separated
digests and cannot recover the content key from them.
Relay blob IDs are hashes of encrypted bytes, so clients must use randomized,
domain-bound authenticated encryption and must not reuse identical blob
ciphertext across domains; domain-scoped storage does not hide identical IDs
from the server operator.

Supported production deployments must:

- terminate modern TLS before application routes, validate the configured
  public certificate, and keep the plaintext Node port private;
- expose only `/v1/pairing/*` and authenticated `/v1/relay/tenants/*` through
  public application ingress; keep `/livez`, `/readyz`, `/metrics`, operator
  `POST /v1/relay/tenants`, and future operator routes on a loopback or private
  management network;
- use a unique PostgreSQL role and a database unavailable from the public net;
- treat the fixed PostgreSQL relay-wake channel as an internal acceleration
  path: its payload contains only tenant/domain routing UUIDs, and durable fetch
  remains authoritative if a hint is forged, duplicated, or lost;
- store database credentials in an operator-managed secret, not an image;
- keep `.env`, TLS material, and live-test access credentials out of both Git
  and the Docker build context;
- isolate and rotate the operator provisioning credential, and do not expose
  the provisioning route through public application ingress;
- keep each tenant-provisioning credential private and independent: it creates
  additional domains and can rotate, while domain-administration credentials
  cannot expand tenant scope;
- deliver newly issued domain-administration and member credentials exactly
  once into an approved client secret store;
- rotate a domain-administration or member credential by generating its
  replacement locally and sending only the domain-separated digest; an exact
  retry may use either side of that one recorded rotation;
- deliver short-lived member-admission credentials only through an
  authenticated, user-approved channel; possession grants the frozen relay
  capabilities but proves neither a Facets principal nor a Shared Space role;
- retain encrypted backups and prove restore regularly;
- checkpoint PostgreSQL and the opaque-blob volume together so metadata cannot
  point at missing content or retained files lose their authority records;
- retain host/edge-level request and distributed rate limits in addition to
  the Node's bounded per-process fixed-surface controls;
- collect logs without authorization headers, request bodies, ciphertext, or
  client IP addresses;
- run the container as an unprivileged user with a read-only root filesystem;
- update the immutable image rather than modifying a running container.
- label persistent images with the full committed revision and source-tree ID,
  verify the running container uses that image, and record the same validated
  revision in coordinated checkpoint manifests;

The pairing, member-admission, replica-message, and encrypted-blob APIs are
security checkpoints, not a production hosted-service declaration. The message
relay has separate tenant/domain message/blob count and byte ceilings plus
member, admission, and credential-rotation bounds. Blob upload verifies the declared length and SHA-256 content
address before an atomic filesystem commit, but failed post-write metadata
commits can leave unreferenced files until orphan collection is implemented.
An administrator can collect terminal admissions only after their 30-day
response-recovery window; message/blob retention and audit-history policy are
not yet implemented. The service applies bounded per-process credential/route,
direct-connection, and concurrency limits, but not coordinated
distributed/account-level rate limits. Compromised member authorization can
read or publish opaque envelopes within its capabilities even though it cannot
decrypt them without the content key. Account admission, operator-credential
rotation, abuse resistance, distributed rate limiting, retention policy, independent
review, periodic off-host and fresh-machine backup/restore drills, and hosted
incident procedures remain required before public exposure. The checked-in
operations bundle proves an encrypted same-host restore into isolated fresh
volumes, but that is a recovery primitive rather than a production backup
policy.

The checked-in Caddy policy is a boundary test, not an authentication layer: it
returns `404` for private management paths and forwards the two versioned
application families. Tenant-scoped relay endpoints still enforce their bearer
capabilities in the Node. The loopback management listener contains both route
families and must not be published to a LAN or the internet.
