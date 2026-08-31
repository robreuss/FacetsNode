# syntax=docker/dockerfile:1.7
ARG FACETS_SERVER_SOURCE_REVISION=unknown
ARG FACETS_SERVER_SOURCE_TREE=unknown

FROM golang:1.26.5-bookworm AS build

ARG FACETS_SERVER_SOURCE_REVISION
ARG FACETS_SERVER_SOURCE_TREE

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN for value in "$FACETS_SERVER_SOURCE_REVISION" "$FACETS_SERVER_SOURCE_TREE"; do \
        [ "$value" = unknown ] || printf '%s\n' "$value" | grep -Eq '^[0-9a-f]{40}$'; \
    done && \
    CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
        -o /out/facets-device-sync-server ./cmd/facets-device-sync-server && \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
        -o /out/facets-shared-spaces-server ./cmd/facets-shared-spaces-server && \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
        -o /out/facets-compute-pool-server ./cmd/facets-compute-pool-server && \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
        -o /out/facets-backup-custody-server ./cmd/facets-backup-custody-server && \
    mkdir -p /out/blobs /out/backup-custody/custody && \
    chmod 0700 /out/backup-custody /out/backup-custody/custody && \
    chown -R 65532:65532 /out/blobs /out/backup-custody

FROM scratch AS device-sync
ARG FACETS_SERVER_SOURCE_REVISION
ARG FACETS_SERVER_SOURCE_TREE
LABEL org.opencontainers.image.title="Facets Device Sync Server" \
      org.opencontainers.image.revision="$FACETS_SERVER_SOURCE_REVISION" \
      org.opencontainers.image.source-tree="$FACETS_SERVER_SOURCE_TREE"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/facets-device-sync-server /facets-device-sync-server
COPY --chown=65532:65532 --from=build /out/blobs /var/lib/facets-device-sync/blobs
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/facets-device-sync-server"]

FROM scratch AS shared-spaces
ARG FACETS_SERVER_SOURCE_REVISION
ARG FACETS_SERVER_SOURCE_TREE
LABEL org.opencontainers.image.title="Facets Shared Spaces Server" \
      org.opencontainers.image.revision="$FACETS_SERVER_SOURCE_REVISION" \
      org.opencontainers.image.source-tree="$FACETS_SERVER_SOURCE_TREE"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/facets-shared-spaces-server /facets-shared-spaces-server
COPY --chown=65532:65532 --from=build /out/blobs /var/lib/facets-shared-spaces/blobs
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/facets-shared-spaces-server"]

FROM scratch AS compute-pool
ARG FACETS_SERVER_SOURCE_REVISION
ARG FACETS_SERVER_SOURCE_TREE
LABEL org.opencontainers.image.title="Facets Compute Pool Service" \
      org.opencontainers.image.revision="$FACETS_SERVER_SOURCE_REVISION" \
      org.opencontainers.image.source-tree="$FACETS_SERVER_SOURCE_TREE"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/facets-compute-pool-server /facets-compute-pool-server
COPY --chown=65532:65532 --from=build /out/blobs /var/lib/facets-compute-pool/blobs
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/facets-compute-pool-server"]

FROM scratch AS backup-custody
ARG FACETS_SERVER_SOURCE_REVISION
ARG FACETS_SERVER_SOURCE_TREE
LABEL org.opencontainers.image.title="Facets Backup Custody Service" \
      org.opencontainers.image.revision="$FACETS_SERVER_SOURCE_REVISION" \
      org.opencontainers.image.source-tree="$FACETS_SERVER_SOURCE_TREE"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/facets-backup-custody-server /facets-backup-custody-server
COPY --chown=65532:65532 --from=build /out/backup-custody /var/lib/facets-backup-custody
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/facets-backup-custody-server"]
