# Contributing

Keep changes narrow and preserve the relay's ignorance of encrypted payloads.
Protocol behavior must be represented by versioned public fixtures and tested
independently of any Facets app database.

The portable transport fixture is a single byte-identical artifact in both
repositories:

- `internal/protocol/testdata/facets-server-transport-portable-v1.json`
- `../Facets/Packages/FacetsDeveloperKit/Tests/FacetsNodeClientTests/Fixtures/facets-server-transport-portable-v1.json`

Do not independently reformat either copy. A protocol revision updates both
copies, their independent decoder tests, and the transport-contract document in
the same review.

Before proposing a change, run:

```sh
gofmt -w .
go test ./...
go vet ./...
```

Never commit production bearer tokens, database URLs, private keys, decrypted
payloads, or logs containing them. Security-sensitive behavior requires tests
for malformed input, replay, collision, expiry, authorization separation, and
restart-safe idempotence.
