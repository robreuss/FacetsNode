# syntax=docker/dockerfile:1.7
FROM golang:1.26.5-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/facets-node ./cmd/facets-node && \
    mkdir -p /out/blobs && chown 65532:65532 /out/blobs

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/facets-node /facets-node
COPY --chown=65532:65532 --from=build /out/blobs /var/lib/facets-node/blobs
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/facets-node"]
