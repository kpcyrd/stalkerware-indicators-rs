FROM rust:alpine3.20
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN apk add --no-cache musl-dev
WORKDIR /code
COPY . .
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --examples --verbose && \
    cp -v /var/cache/buildkit/target/release/examples/lint /
RUN strip /lint

FROM alpine:3.20
RUN apk add --no-cache libgcc
COPY --from=0 /lint /usr/local/bin/
ENTRYPOINT ["lint"]
