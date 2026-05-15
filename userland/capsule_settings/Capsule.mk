CAPSULE_SLUG             := settings
CAPSULE_HANDLE           := settings
CAPSULE_DOMAIN           := systems.nonos
CAPSULE_DIR              := userland/capsule_settings
CAPSULE_BIN_NAME         := settings
CAPSULE_FEATURE          := nonos-capsule-settings
CAPSULE_NAMESPACE        := systems.nonos.settings
CAPSULE_SERVICE_ENDPOINT := service:4728:settings
CAPSULE_REPLY_ENDPOINT   := reply:4729:endpoint.settings.reply
# IPC | Memory = 0x08 | 0x10 = 0x18
CAPSULE_REQUIRED_CAPS    := 0x18

include nonos-mk/capsule.mk
