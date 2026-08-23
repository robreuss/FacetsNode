FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates tor \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 -o debian-tor -g debian-tor \
        /var/lib/tor/facets-onion

COPY --chown=debian-tor:debian-tor torrc /etc/tor/facets-torrc

USER debian-tor
ENTRYPOINT ["tor", "-f", "/etc/tor/facets-torrc"]
