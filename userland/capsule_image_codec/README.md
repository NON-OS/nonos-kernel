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
