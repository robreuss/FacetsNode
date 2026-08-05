# Security policy

Facets Node carries high-value encrypted state and authorization capabilities.
Please do not disclose a suspected vulnerability in a public issue. Until a
dedicated security address is published, contact the project owner privately
through the repository hosting account.

The Node is an opaque transport, not a key server. Clients encrypt replica
messages with a separate domain content key. The operator, domain
administration, and member bearer credentials authorize routing operations but
must never be reused as content-encryption keys. The Node stores only their
domain-separated digests and cannot recover the content key from them.

Supported production deployments must:

- terminate modern TLS before the Node API and keep the container port private;
- use a unique PostgreSQL role and a database unavailable from the public net;
- store database credentials in an operator-managed secret, not an image;
- isolate and rotate the operator provisioning credential, and do not expose
  the provisioning route through public application ingress;
- deliver newly issued domain-administration and member credentials exactly
  once into an approved client secret store;
- retain encrypted backups and prove restore regularly;
- set host-level request limits and rate limits in addition to Node limits;
- collect logs without authorization headers, request bodies, ciphertext, or
  client IP addresses;
- run the container as an unprivileged user with a read-only root filesystem;
- update the immutable image rather than modifying a running container.

The pairing and replica-message APIs are security checkpoints, not a production
hosted-service declaration. The message relay has per-domain message and stored
ciphertext quotas, but it does not yet collect retained data or apply
distributed/account-level rate limits. Compromised member authorization can
read or publish opaque envelopes within its capabilities even though it cannot
decrypt them without the content key. Account admission, credential rotation,
abuse resistance, distributed rate limiting, retention policy, independent
review, backup/restore drills, and hosted incident procedures remain required
before public exposure.
