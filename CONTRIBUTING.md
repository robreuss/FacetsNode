# Contributing

Keep changes narrow and preserve the relay's ignorance of encrypted payloads.
Protocol behavior must be represented by versioned public fixtures and tested
independently of any Facets app database.

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
