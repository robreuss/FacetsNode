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
    mkdir -p /out/blobs && chown 65532:65532 /out/blobs

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
