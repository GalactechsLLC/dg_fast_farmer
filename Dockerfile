FROM --platform=linux/amd64 rust:1.75-slim-bullseye AS toolchain
RUN echo "fn main() {println!(\"dummy\");}" > dummy.rs

FROM toolchain as sources
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY --from=toolchain dummy.rs src/main.rs
# Build the project
RUN cargo fetch

FROM sources as build
COPY src/ src/
RUN mkdir /build
RUN cargo build --release && mv /target/release/* /build

FROM debian:bullseye-slim AS dg_fast_farmer
LABEL authors="James Hoerr" \
    name="dg_fast_farmer" \
    version="2.0.0" \
    description="A lite farmer for the Chia Blockchain." \
    license="Apache-2.0" \
    homepage="https://github.com/GalactechsLLC/dg_fast_farmer" \
    repository="https://github.com/GalactechsLLC/dg_fast_farmer"
RUN apt update -y \
    && apt install -y ca-certificates \
    && apt autoremove -y \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build --chmod=0755 /build/ff /usr/local/bin/
CMD ["ff run"]