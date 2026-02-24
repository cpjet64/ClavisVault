FROM rust:1.93.1-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p clavisvault-server

FROM debian:bookworm-slim
RUN useradd -r -m -d /var/lib/clavisvault clavisvault
WORKDIR /var/lib/clavisvault
RUN mkdir -p /var/lib/clavisvault
RUN chown -R clavisvault:clavisvault /var/lib/clavisvault
COPY --from=builder /app/target/release/clavisvault-server /usr/local/bin/clavisvault-server
USER clavisvault
EXPOSE 51821/udp
ENTRYPOINT ["/usr/local/bin/clavisvault-server"]
