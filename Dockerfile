# syntax=docker/dockerfile:1.7
ARG FACETS_NODE_SOURCE_REVISION=unknown
ARG FACETS_NODE_SOURCE_TREE=unknown

FROM golang:1.26.5-bookworm AS build

ARG FACETS_NODE_SOURCE_REVISION
ARG FACETS_NODE_SOURCE_TREE

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN for value in "$FACETS_NODE_SOURCE_REVISION" "$FACETS_NODE_SOURCE_TREE"; do \
        [ "$value" = unknown ] || printf '%s\n' "$value" | grep -Eq '^[0-9a-f]{40}$'; \
    done && \
    CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/facets-node ./cmd/facets-node && \
    mkdir -p /out/blobs && chown 65532:65532 /out/blobs

FROM scratch
ARG FACETS_NODE_SOURCE_REVISION
ARG FACETS_NODE_SOURCE_TREE
LABEL org.opencontainers.image.revision="$FACETS_NODE_SOURCE_REVISION" \
      org.opencontainers.image.source-tree="$FACETS_NODE_SOURCE_TREE"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/facets-node /facets-node
COPY --chown=65532:65532 --from=build /out/blobs /var/lib/facets-node/blobs
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/facets-node"]
