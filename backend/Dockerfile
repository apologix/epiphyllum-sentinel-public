FROM rust:1.90.0-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS build
WORKDIR /workspace
COPY backend backend
COPY corpus corpus
COPY datasets datasets
# mcp.rs embebe la CA pública del laboratorio con include_bytes!.
COPY lab/lab-ca.pem lab/lab-ca.pem
WORKDIR /workspace/backend
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/workspace/backend/target cargo build --release --locked && cp target/release/epiphyllum-sentinel /sentinel && cp target/release/generator /generator
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && mkdir -p /data/logs && chmod 1777 /data/logs && mkdir /secrets && chown 10001:10001 /secrets && chmod 700 /secrets
COPY --from=build /sentinel /usr/local/bin/sentinel
COPY --from=build /generator /usr/local/bin/generator
USER 10001:10001
EXPOSE 8000
CMD ["sentinel"]
