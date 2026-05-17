# capsule_image_codec

`capsule_image_codec` is a userland decode service that accepts image
payloads over IPC and returns a shared ARGB8888 surface handle.

Service endpoint: `service:4412:image_codec`.
Reply endpoint: `reply:4413:endpoint.image_codec.reply`.

Ops:
- `OP_HEALTHCHECK`
- `OP_DECODE_PNG`
- `OP_DECODE_BMP`
- `OP_DECODE_LZ4_RAW`
- `OP_DECODE_JPEG`

## Authority

Required caps `0x1919` (CoreExec | IPC | Memory | Debug |
GraphicsDisplayQuery | GraphicsSurfaceCreate). No driver caps.

## Errors

`NCMP`-shaped envelope. Malformed requests get a deterministic typed
errno, never a silent drop: `E_BAD_MAGIC` (wrong magic), `E_BAD_VERSION`
(version mismatch), `E_BAD_LEN` (short/!= declared len), `E_BAD_OP`
(unknown op), `E_INVAL` (bad body), `E_UNSUPPORTED` (codec/format not
supported), `E_NOMEM` (surface alloc failed).

## Kernel integration

Embedded + spawned via signed `spawn_verified`
(`src/userspace/capsule_image_codec/`), cfg-gated by
`nonos-capsule-image-codec` in `src/userspace/init/entry.rs`,
bundled in the `microkernel-desktop-gui` profile.
