CAPSULE_SLUG             := clipboard
CAPSULE_HANDLE           := clipboard
CAPSULE_DOMAIN           := systems.nonos
CAPSULE_DIR              := userland/capsule_clipboard
CAPSULE_BIN_NAME         := clipboard
CAPSULE_FEATURE          := nonos-capsule-clipboard
CAPSULE_NAMESPACE        := systems.nonos.clipboard
CAPSULE_SERVICE_ENDPOINT := service:4414:clipboard
CAPSULE_REPLY_ENDPOINT   := reply:4415:endpoint.clipboard.reply
# IPC | Memory = 0x08 | 0x10 = 0x18
CAPSULE_REQUIRED_CAPS    := 0x18

include nonos-mk/capsule.mk
