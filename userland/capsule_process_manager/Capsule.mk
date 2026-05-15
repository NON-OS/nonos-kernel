CAPSULE_SLUG             := process-manager
CAPSULE_HANDLE           := process_manager
CAPSULE_DOMAIN           := systems.nonos
CAPSULE_DIR              := userland/capsule_process_manager
CAPSULE_BIN_NAME         := process_manager
CAPSULE_FEATURE          := nonos-capsule-process-manager
CAPSULE_NAMESPACE        := systems.nonos.process_manager
CAPSULE_SERVICE_ENDPOINT := service:4730:process_manager
CAPSULE_REPLY_ENDPOINT   := reply:4731:endpoint.process_manager.reply
# IPC | Memory = 0x08 | 0x10 = 0x18
CAPSULE_REQUIRED_CAPS    := 0x18

include nonos-mk/capsule.mk
