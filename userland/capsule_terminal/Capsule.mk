CAPSULE_SLUG             := terminal
CAPSULE_HANDLE           := terminal
CAPSULE_DOMAIN           := systems.nonos
CAPSULE_DIR              := userland/capsule_terminal
CAPSULE_BIN_NAME         := terminal
CAPSULE_FEATURE          := nonos-capsule-terminal
CAPSULE_NAMESPACE        := systems.nonos.terminal
CAPSULE_SERVICE_ENDPOINT := service:4722:terminal
CAPSULE_REPLY_ENDPOINT   := reply:4723:endpoint.terminal.reply
# IPC | Memory = 0x08 | 0x10 = 0x18
CAPSULE_REQUIRED_CAPS    := 0x18

include nonos-mk/capsule.mk
