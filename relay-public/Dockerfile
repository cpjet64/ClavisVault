FROM rust:1.93.1-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p clavisvault-relay

FROM debian:bookworm-slim
RUN useradd -r -m -d /var/lib/clavisvault clavisvault
WORKDIR /var/lib/clavisvault
COPY --from=builder /app/target/release/clavisvault-relay /usr/local/bin/clavisvault-relay
USER clavisvault
EXPOSE 51820/udp
ENTRYPOINT ["/usr/local/bin/clavisvault-relay"]
