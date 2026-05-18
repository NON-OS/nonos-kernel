# capsule_clipboard

## Role

`capsule_clipboard` is a bounded userland clipboard service capsule.

## Interface contract

Ops:

- `HEALTHCHECK`
- `COPY`
- `PASTE`
- `HISTORY_LIST`
- `HISTORY_GET`
- `CLEAR`

## Runtime behavior

- Stores typed clipboard entries in a bounded history ring.
- Enforces default limits: depth 16, total bytes 256 KiB, entry bytes 64 KiB.
- Returns deterministic errno on malformed requests or out-of-range history reads.

## Verification

- `cargo +nightly check --manifest-path userland/capsule_clipboard/Cargo.toml --target userland/{x86_64,aarch64,riscv64}-nonos-user.json -Z build-std=core,alloc -Z json-target-spec`
- `make nonos-mk-clipboard`
- `make nonos-mk-clipboard-sign`
- `./nonos-ci/run-static-checks.sh`
