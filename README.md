# Facets Node

Facets Node is the open-source, self-hostable store-and-forward service for
Facets Sync and Shared Spaces. The project is a Go modular monolith packaged as
an OCI image. Hosted Facets infrastructure and a user's own server run the same
protocol implementation.

The implemented roles are an attended device-pairing rendezvous and the first
general replica-message relay. They store only random routing identifiers,
domain-separated capability digests, bounded metadata, and client-encrypted
envelopes. Pairing payload kinds, FEF messages, principal IDs, device IDs, key
material, and bearer capabilities are never stored in plaintext.

This repository is intentionally separate from the Facets application. Relay
development after a shared-contract freeze does not require changes to the
Facets core codebase.

## Current scope

- PostgreSQL-backed, restart-safe pairing routes and opaque envelopes
- Separate sponsor and candidate bearer capabilities
- Exact-retry idempotence and message-ID collision rejection
- Role-separated fetch, receiver acknowledgement, expiry, and sponsor close
- Request limits, timeouts, structured redacted logs, health, and metrics
- Local Compose profile and a single production OCI image
- Cross-language tests against the public Swift rendezvous fixture
- Explicit tenant, replica-domain, and member scope on every relay operation
- Capability-scoped relay membership with immediate expiry and revocation
- Opaque, monotonic catch-up cursors and per-member accepted/applied facts
- Per-domain message/blob counts and total stored-byte quotas
- PostgreSQL-backed concurrent publication with restart-safe ordering
- Cross-language tests against the public Swift replica-carrier fixture
- Domain-scoped, content-addressed encrypted-blob storage on a separate volume
- Streaming blob upload with digest verification and Range-capable GET/HEAD

Resumable/multipart blob upload, checkpoints, retention and orphan collection,
hosted object storage/account admission, Shared Space membership, billing, and
compute are later modules. The checkpoint capability name is reserved but its
endpoint is not yet implemented. No valid FEF, device grant, payment record, or
Shared Space membership will implicitly grant compute execution.

## Development

Requirements are Go 1.26 or newer and PostgreSQL 17 or newer.

```sh
go test ./...
go vet ./...
```

To exercise the PostgreSQL integration suite, set a disposable database URL:

```sh
FACETS_NODE_TEST_DATABASE_URL='postgres://facets:facets@localhost:5432/facets?sslmode=disable' go test ./...
```

## Running with Compose

```sh
cp .env.example .env
# Replace the placeholder with a unique value, for example: openssl rand -hex 32
docker compose up --build
```

The development profile binds the API to `127.0.0.1:8080`. Production ingress
must terminate TLS in front of the Node; never expose its plaintext container
port directly to an untrusted network. The Compose stack refuses to start until
`FACETS_NODE_POSTGRES_PASSWORD` is supplied in the ignored `.env` file; never
reuse that database credential for any Node or external service.

Compose persists PostgreSQL metadata and opaque blob bytes in separate named
volumes. A valid backup/restore or host migration must treat both volumes as one
checkpoint. The filesystem blob adapter is the self-hosted checkpoint; hosted
multi-instance deployment still requires the same narrow content-store
interface to be backed by reviewed object storage.

## Security boundary

Pairing, relay-member, relay-administration, and operator bearer tokens are
independent high-entropy secrets. Send them only in the `Authorization` header
over TLS. Facets Node does not log authorization headers, request bodies,
ciphertext, or client IP addresses. See [SECURITY.md](SECURITY.md) for reporting
and deployment requirements, and
[docs/replica-relay-api.md](docs/replica-relay-api.md) for the relay contract.

## License

Apache License 2.0.
