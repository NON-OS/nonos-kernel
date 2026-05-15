# capsule_wallpaper

## Role

`capsule_wallpaper` is a long-lived wallpaper service capsule. It receives IPC
requests for wallpaper updates, policy changes, and fades, then pushes updates
to compositor using a full-screen shared surface.

## Interface contract

Ops:

- `HEALTHCHECK`
- `SET_WALLPAPER`
- `GET_WALLPAPER`
- `SET_POLICY`
- `FADE`

`SET_WALLPAPER` supports two request forms:

- 8-byte solid-color payload (`argb`, pad)
- decode payload (`kind`, `width`, `height`, `payload_len`, bytes) where
  `kind` = PNG/BMP/LZ4_RAW/JPEG and bytes are decoded through `nonos_toolkit`

## Runtime behavior

- Discovers `desktop_shell` and `compositor` services during setup.
- Allocates and registers one full-screen ARGB8888 surface.
- Shares the surface handle and submits it as the bottom compositor layer.
- Applies updates in place and sends compositor damage commits.
- Maintains current color, policy, and fade timeline in capsule state.

## Privacy and persistence

- No file-system persistence.
- No input capture.
- No window-policy ownership.
- Pixels exist only in mapped userland surface memory and compositor-visible
  surface handles.

## Failure model

- Invalid request envelopes return `E_INVAL`.
- Unknown opcodes return `E_BAD_OP`.
- Decode failures return `E_INVAL`.
- Setup fails closed if required services or surface allocation are unavailable.

## Verification

- Triple-target build check:
  `cargo +nightly check --manifest-path userland/capsule_wallpaper/Cargo.toml --target userland/{x86_64,aarch64,riscv64}-nonos-user.json -Z build-std=core,alloc -Z json-target-spec`
- Release build target: `make nonos-mk-wallpaper`
- Sign target: `make nonos-mk-wallpaper-sign`
- Static gate: `./nonos-ci/run-static-checks.sh`
