# Onion-only Facets Server ingress

The optional onion profile exposes the reviewed Facets application protocol
through a Tor v3 onion service while publishing no application or management
port on the host. It is separate from the ordinary direct-HTTPS deployment;
there is no automatic fallback between them.

## Boundary

The profile creates three network compartments and one socket boundary:

1. PostgreSQL and FacetsNode share the existing internal `private` network.
2. FacetsNode and onion Caddy share `onion-application`.
3. Only Tor joins the non-internal `tor-egress` network.
4. Tor reaches Caddy only through a dedicated Unix-domain socket volume, not
   through a shared IP network. No other workload mounts that socket.

The ordinary Caddy service is disabled and both inherited host port lists are
reset. Tor has no SOCKS or control listener and publishes no port. Its only
onion mapping is virtual port 443 to Caddy's Unix socket. Caddy forwards only
the same application allowlist as direct ingress; health, readiness, metrics,
operator provisioning, PostgreSQL, and blob files remain private.

Tor consensus, descriptor, and runtime state use a bounded 128 MiB disposable
tmpfs. Container health requires both the persistent onion hostname and Tor's
explicit `Bootstrapped 100%` notice; creating the onion identity alone is not
readiness. Only the much smaller onion identity directory is persistent.

The persistent onion volume contains the hostname and Tor master identity
state and is created mode 0700 for the unprivileged `debian-tor` user. Treat
the volume as deployment identity custody: disclosure permits route
impersonation, while loss changes the onion hostname. It contains no Facets
content key, bearer, manifest-signing key, or deployment-signing key.

## Privacy-safe traffic marker

Caddy deletes standard forwarding/location headers and overwrites two private
headers: a fixed `tor-onion` marker and an independently generated 32-byte
token. FacetsNode accepts the marker only when the token matches its protected
configuration, strips both headers before application handling, and then:

- retains per-bearer or per-rendezvous-route identity limits using only
  one-way digests;
- uses one bounded connection budget per traffic surface rather than a client
  address; and
- never trusts a public `Forwarded`, `X-Forwarded-For`, or `X-Real-IP` value.

The marker affects traffic accounting only. It grants no relay, Device Sync,
Shared Space, authority, deployment, or content capability.

## Development launch

Generate a token independent from all other secrets:

```sh
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
```

Set the corresponding `FACETS_DEVICE_SYNC_ONION_INGRESS_TOKEN` or
`FACETS_SHARED_SPACES_ONION_INGRESS_TOKEN` in the service environment file.
The Compose override uses reset/override tags and therefore requires Docker
Compose 2.24.4 or newer.

Device Sync:

```sh
docker compose -f compose.yaml \
  -f deploy/onion/device-sync.compose.yaml config
docker compose -f compose.yaml \
  -f deploy/onion/device-sync.compose.yaml up --build -d
docker compose -f compose.yaml \
  -f deploy/onion/device-sync.compose.yaml exec -T tor \
  cat /var/lib/tor/facets-onion/hostname
```

Shared Spaces:

```sh
docker compose --env-file deploy/shared-spaces/.env \
  -f deploy/shared-spaces/compose.yaml \
  -f deploy/onion/shared-spaces.compose.yaml config
docker compose --env-file deploy/shared-spaces/.env \
  -f deploy/shared-spaces/compose.yaml \
  -f deploy/onion/shared-spaces.compose.yaml up --build -d
docker compose --env-file deploy/shared-spaces/.env \
  -f deploy/shared-spaces/compose.yaml \
  -f deploy/onion/shared-spaces.compose.yaml exec -T tor \
  cat /var/lib/tor/facets-onion/hostname
```

The mounted TLS keypair remains required. Its SPKI digest belongs in the
Facets-signed route descriptor. Shared Spaces must also use its resulting
`https://<hostname>.onion` origin before issuing compute capabilities. Product
automation will eventually generate these values and manifests; this
checkpoint does not ask an end user to operate Compose or handle keys.

## Isolated Device Sync runtime checkpoint

On 2026-08-23, committed revision
`46e1d5831e768d511da18351471d77fbd7c75329` and source tree
`1e25c1a7d078cbbafb2c0f8bb6ed1c3c805320da` passed an isolated Device Sync
onion deployment gate on Facets Box development VM 190:

- the exact release archive built both server binaries and ran the complete Go
  suite inside the image build;
- PostgreSQL, FacetsNode, onion Caddy, and Tor reached their required running
  or healthy states, with Tor 0.4.9.11 explicitly reporting 100% bootstrap;
- the running Device Sync image revision and source-tree labels matched the
  release, and none of the isolated project's containers published a host
  port;
- Tor had the only egress-capable network, Caddy and Tor shared only the
  dedicated Unix socket, and PostgreSQL remained confined to the internal
  application network;
- the onion identity directory was mode 2700, its hostname and secret key were
  mode 0600, and the Tor-to-Caddy socket was reachable only through its
  dedicated volume;
- a separate Tor client reached the onion route through SOCKS with the mounted
  certificate's SPKI pin: the private readiness path returned 404 and an empty
  pairing request reached application validation and returned 400;
- replacing that SPKI pin caused curl to abort with error 90 before receiving
  an HTTP response;
- a container-network packet capture of the probe saw only client-to-SOCKS
  traffic and no direct client DNS, TCP 80, or TCP 443 flow; and
- restarting all four containers retained the onion hostname, returned to
  readiness in 31 seconds, and produced no Tor storage error with the 128 MiB
  runtime tmpfs.

The canonical direct-HTTPS Device Sync and Shared Spaces deployments continued
running during this isolated checkpoint. This is container and LAN deployment
evidence, not physical Apple-client or public-network acceptance.

## Verification boundary

Repository tests prove configuration structure, allowlist parity, strict
ingress-token handling, privacy-safe limiter keys, and the absence of a
declared host listener. The isolated checkpoint additionally proves a built
Tor image, bootstrap, SPKI enforcement, restart identity continuity, and the
described container packet boundary. It does not prove public/off-LAN Tor
reachability, a physical iPhone or Mac, Apple-client DNS behavior, full Device
Sync flows, Shared Spaces onion runtime, onion-state migration, or production
deployment-authority onboarding. Those remain separate gates.
