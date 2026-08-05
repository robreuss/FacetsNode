# Security policy

Facets Node carries high-value encrypted state and authorization capabilities.
Please do not disclose a suspected vulnerability in a public issue. Until a
dedicated security address is published, contact the project owner privately
through the repository hosting account.

Supported production deployments must:

- terminate modern TLS before the Node API and keep the container port private;
- use a unique PostgreSQL role and a database unavailable from the public net;
- store database credentials in an operator-managed secret, not an image;
- retain encrypted backups and prove restore regularly;
- set host-level request limits and rate limits in addition to Node limits;
- collect logs without authorization headers, request bodies, ciphertext, or
  client IP addresses;
- run the container as an unprivileged user with a read-only root filesystem;
- update the immutable image rather than modifying a running container.

The current pairing API is an early security checkpoint, not a production
hosted-service declaration. Account admission, abuse resistance, distributed
rate limiting, independent review, backup/restore drills, and hosted incident
procedures remain required before public exposure.
