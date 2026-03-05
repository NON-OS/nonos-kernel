# Reproducible builder for the reference powersoftau binary.
# IMPORTANT: replace POWERSOFTAU_COMMIT with an audited SHA for production.
FROM rust:1.72-buster AS builder

ARG POWERSOFTAU_REPO="https://github.com/zkcrypto/powersoftau.git"
ARG POWERSOFTAU_COMMIT="main"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates build-essential pkg-config libssl-dev jq && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work
RUN git clone --depth 1 ${POWERSOFTAU_REPO} powersoftau_src || true
WORKDIR /work/powersoftau_src
RUN if [ "${POWERSOFTAU_COMMIT}" != "main" ]; then git fetch --depth=1 origin ${POWERSOFTAU_COMMIT} && git checkout ${POWERSOFTAU_COMMIT}; fi
RUN cargo build --release --locked

FROM debian:buster-slim
COPY --from=builder /work/powersoftau_src/target/release/powersoftau /usr/local/bin/powersoftau
RUN chmod +x /usr/local/bin/powersoftau
ENTRYPOINT ["/usr/local/bin/powersoftau"]
CMD ["--help"]
