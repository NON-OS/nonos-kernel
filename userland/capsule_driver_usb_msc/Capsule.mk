# usb_msc — USB Mass Storage class driver. Consumes USB configuration
# descriptors and builds BOT/SCSI command blocks for a USB
# host-controller service. It owns class framing only; xHCI owns
# endpoint configuration and bulk transfer mechanics.

CAPSULE_SLUG             := driver-usb-msc
CAPSULE_HANDLE           := driver.usb_msc0
CAPSULE_DOMAIN           := systems.nonos
CAPSULE_DIR              := userland/capsule_driver_usb_msc
CAPSULE_BIN_NAME         := driver_usb_msc
CAPSULE_FEATURE          := nonos-capsule-driver-usb-msc
CAPSULE_NAMESPACE        := systems.nonos.driver.usb_msc0
CAPSULE_SERVICE_ENDPOINT := service:4224:driver.usb_msc0
CAPSULE_REPLY_ENDPOINT   := reply:4225:endpoint.4294967315
# IPC|Memory = 0x18. No Driver/DeviceEnum/Mmio/Irq/Dma/Pio.
CAPSULE_REQUIRED_CAPS    := 0x18

include nonos-mk/capsule.mk
