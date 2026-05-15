CAPSULE_SLUG             := file-manager
CAPSULE_HANDLE           := file_manager
CAPSULE_DOMAIN           := systems.nonos
CAPSULE_DIR              := userland/capsule_file_manager
CAPSULE_BIN_NAME         := file_manager
CAPSULE_FEATURE          := nonos-capsule-file-manager
CAPSULE_NAMESPACE        := systems.nonos.file_manager
CAPSULE_SERVICE_ENDPOINT := service:4724:file_manager
CAPSULE_REPLY_ENDPOINT   := reply:4725:endpoint.file_manager.reply
# IPC | Memory = 0x08 | 0x10 = 0x18
CAPSULE_REQUIRED_CAPS    := 0x18

include nonos-mk/capsule.mk
