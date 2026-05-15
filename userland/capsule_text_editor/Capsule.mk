CAPSULE_SLUG             := text-editor
CAPSULE_HANDLE           := text_editor
CAPSULE_DOMAIN           := systems.nonos
CAPSULE_DIR              := userland/capsule_text_editor
CAPSULE_BIN_NAME         := text_editor
CAPSULE_FEATURE          := nonos-capsule-text-editor
CAPSULE_NAMESPACE        := systems.nonos.text_editor
CAPSULE_SERVICE_ENDPOINT := service:4726:text_editor
CAPSULE_REPLY_ENDPOINT   := reply:4727:endpoint.text_editor.reply
# IPC | Memory = 0x08 | 0x10 = 0x18
CAPSULE_REQUIRED_CAPS    := 0x18

include nonos-mk/capsule.mk
