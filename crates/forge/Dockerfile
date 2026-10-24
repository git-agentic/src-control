# sc-forge image. Build from the repository root:
#   docker build -f crates/forge/Dockerfile -t sc-forge .
# Base images are pinned by digest; bump them together with rust-toolchain.toml.

FROM rust:1.96.1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p scl-forge --bin sc-forge

# trixie, not bookworm: sc-forge needs git 2.40 or newer (merge-tree --write-tree, quarantine
# naming) and bookworm ships 2.39. No sshd, no shell tooling beyond the base.
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin forge \
 && mkdir /data && chown forge:forge /data
COPY --from=build /src/target/release/sc-forge /usr/local/bin/sc-forge
USER forge
VOLUME /data
EXPOSE 3000
# SIGTERM drains (see docs/FORGE-OPERATIONS.md); give the orchestrator longer than --shutdown-timeout.
STOPSIGNAL SIGTERM
# tini is PID 1: it reaps the git processes that outlive a killed transport (orphans are re-parented
# to PID 1 and would otherwise stay zombies until pids.max runs out) and forwards SIGTERM.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sc-forge"]
CMD ["--help"]
