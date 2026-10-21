FROM rust:1.99-bookworm@sha256:5c1a1732ac3f77635b24d397ceb67b4d9ea61de348f68c0aa54a79fd01e65c69 AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends musl-tools pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --target x86_64-unknown-linux-musl

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS certs
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

FROM scratch
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/attestation-proxy /attestation-proxy
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT ["/attestation-proxy"]
