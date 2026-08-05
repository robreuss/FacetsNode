# Security policy

Facets Node carries high-value encrypted state and authorization capabilities.
Please do not disclose a suspected vulnerability in a public issue. Until a
dedicated security address is published, contact the project owner privately
through the repository hosting account.

The Node is an opaque transport, not a key server. Clients encrypt replica
messages with a separate domain content key. The operator, domain
administration, member-admission, and member bearer credentials authorize
routing operations but must never be reused as content-encryption keys. The
Node stores only their domain-separated digests and cannot recover the content
key from them.
Relay blob IDs are hashes of encrypted bytes, so clients must use randomized,
domain-bound authenticated encryption and must not reuse identical blob
ciphertext across domains; domain-scoped storage does not hide identical IDs
from the server operator.

Supported production deployments must:

- terminate modern TLS before the Node API and keep the container port private;
- use a unique PostgreSQL role and a database unavailable from the public net;
- store database credentials in an operator-managed secret, not an image;
- isolate and rotate the operator provisioning credential, and do not expose
  the provisioning route through public application ingress;
- deliver newly issued domain-administration and member credentials exactly
  once into an approved client secret store;
- deliver short-lived member-admission credentials only through an
  authenticated, user-approved channel; possession grants the frozen relay
  capabilities but proves neither a Facets principal nor a Shared Space role;
- retain encrypted backups and prove restore regularly;
- checkpoint PostgreSQL and the opaque-blob volume together so metadata cannot
  point at missing content or retained files lose their authority records;
- set host-level request limits and rate limits in addition to Node limits;
- collect logs without authorization headers, request bodies, ciphertext, or
  client IP addresses;
- run the container as an unprivileged user with a read-only root filesystem;
- update the immutable image rather than modifying a running container.

The pairing, member-admission, replica-message, and encrypted-blob APIs are
security checkpoints, not a production hosted-service declaration. The message
relay has per-domain message and stored
ciphertext quotas. Blob upload verifies the declared length and SHA-256 content
address before an atomic filesystem commit, but failed post-write metadata
commits can leave unreferenced files until orphan collection is implemented.
The service does not yet collect retained data or apply
distributed/account-level rate limits. Expired, claimed, and revoked admission
records are not yet collected. Compromised member authorization can
read or publish opaque envelopes within its capabilities even though it cannot
decrypt them without the content key. Account admission, credential rotation,
abuse resistance, distributed rate limiting, retention policy, independent
review, periodic off-host and fresh-machine backup/restore drills, and hosted
incident procedures remain required before public exposure. The checked-in
operations bundle proves an encrypted same-host restore into isolated fresh
volumes, but that is a recovery primitive rather than a production backup
policy.
