CAPSULE_SLUG             := calculator
CAPSULE_HANDLE           := calculator
CAPSULE_DOMAIN           := systems.nonos
CAPSULE_DIR              := userland/capsule_calculator
CAPSULE_BIN_NAME         := calculator
CAPSULE_FEATURE          := nonos-capsule-calculator
CAPSULE_NAMESPACE        := systems.nonos.calculator
CAPSULE_SERVICE_ENDPOINT := service:4720:calculator
CAPSULE_REPLY_ENDPOINT   := reply:4721:endpoint.calculator.reply
# IPC | Memory = 0x08 | 0x10 = 0x18
CAPSULE_REQUIRED_CAPS    := 0x18

include nonos-mk/capsule.mk
