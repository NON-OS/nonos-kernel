CAPSULE_SLUG             := about
CAPSULE_HANDLE           := about
CAPSULE_DOMAIN           := systems.nonos
CAPSULE_DIR              := userland/capsule_about
CAPSULE_BIN_NAME         := about
CAPSULE_FEATURE          := nonos-capsule-about
CAPSULE_NAMESPACE        := systems.nonos.about
CAPSULE_SERVICE_ENDPOINT := service:4710:about
CAPSULE_REPLY_ENDPOINT   := reply:4711:endpoint.about.reply
# IPC | Memory = 0x08 | 0x10 = 0x18
CAPSULE_REQUIRED_CAPS    := 0x18

include nonos-mk/capsule.mk
