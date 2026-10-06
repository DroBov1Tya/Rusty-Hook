# syntax=docker/dockerfile:1.7
# Multi-stage: web (wasm) and server (static musl) build in parallel, runtime is scratch.

ARG RUST_IMAGE=rust:1.99-alpine3.24

FROM ${RUST_IMAGE} AS base
RUN apk add --no-cache musl-dev
WORKDIR /src

# --- wasm frontend ---
FROM base AS web
# Must match the wasm-bindgen crate pinned in crates/web/Cargo.toml.
ARG WASM_BINDGEN_VERSION=0.2.129
RUN apk add --no-cache brotli gzip binaryen \
 && rustup target add wasm32-unknown-unknown
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION} --locked
COPY . .
# wasm-opt features = rustc wasm32 defaults, so it emits nothing browsers lack.
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=target-web,target=/src/target \
    cargo build --release --locked -p web --target wasm32-unknown-unknown \
 && wasm-bindgen --target web --no-typescript --remove-name-section --remove-producers-section \
    --out-dir /dist/pkg --out-name web target/wasm32-unknown-unknown/release/web.wasm \
 && wasm-opt -Oz --strip-debug \
    --enable-bulk-memory --enable-mutable-globals --enable-nontrapping-float-to-int \
    --enable-sign-ext --enable-reference-types --enable-multivalue \
    -o /dist/pkg/web_bg.wasm /dist/pkg/web_bg.wasm \
 && cp -r crates/web/static/. /dist/ \
 && find /dist -type f \( -name '*.wasm' -o -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' \) \
    -exec gzip -9 -k {} \; -exec brotli -q 11 -k {} \;

# --- server ---
FROM base AS server
COPY . .
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=target-server,target=/src/target \
    cargo build --release --locked -p server \
 && cp target/release/rusty-hook /rusty-hook

# --- runtime: one static binary + assets, nothing else ---
FROM scratch
COPY --from=server /rusty-hook /rusty-hook
COPY --from=web /dist /dist
ENV APP_BIND=0.0.0.0:8080 \
    STATIC_DIR=/dist \
    RUST_LOG=info
USER 65534:65534
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=4s --start-period=5s --retries=3 CMD ["/rusty-hook", "healthcheck"]
ENTRYPOINT ["/rusty-hook"]
