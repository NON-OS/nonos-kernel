# ramfs — RAM-resident filesystem capsule. Pure userland service
# capsule with no broker hardware authority; uses Crypto for
# content addressing. The kernel-side mirror provides the IPC
# client surface (`fs::ramfs_capsule::client`) and the in-init
# spawn entry (`spawn_ramfs_capsule`).

CAPSULE_SLUG             := ramfs
CAPSULE_HANDLE           := ramfs
CAPSULE_DOMAIN           := systems.nonos
CAPSULE_DIR              := userland/capsule_ramfs
CAPSULE_BIN_NAME         := ramfs
CAPSULE_FEATURE          := nonos-capsule-ramfs
CAPSULE_NAMESPACE        := systems.nonos.ramfs
CAPSULE_SERVICE_ENDPOINT := service:4096:ramfs
CAPSULE_REPLY_ENDPOINT   := reply:4097:endpoint.4294967297
# IPC | Memory | Crypto = 0x08 | 0x10 | 0x20 = 0x38
CAPSULE_REQUIRED_CAPS    := 0x38
CAPSULE_KERNEL_MIRROR    := src/fs/ramfs_capsule

include nonos-mk/capsule.mk
