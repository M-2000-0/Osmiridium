# syntax=docker/dockerfile:1

FROM rust:1.99 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release --bin osmiridium-cli

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/osmiridium-cli /usr/local/bin/osmiridium

RUN mkdir -p /app/data && \
    useradd --create-home --uid 1000 --shell /usr/sbin/nologin osmiridium && \
    chown -R osmiridium:osmiridium /app

USER osmiridium

EXPOSE 8080 9000-9009

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8080/health || exit 1

ENTRYPOINT ["osmiridium"]
CMD ["--help"]