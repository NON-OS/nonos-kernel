# Boot-handoff Trust Ceremony — Iteration Context Log

**Plan:** `docs/superpowers/plans/2026-05-20-boot-handoff-trust-ceremony.md`
**Branch:** feature/bootloader-hardening
**Merge commit:** 72265e14d (parents 919127580 ours + 7d20c23d5 theirs)
**Started:** 2026-05-20

## Capsule set under ceremony (34 — from nonos-sign/tests/artifacts.rs)

| Slug (make)        | Prefix (key files)       | Boot-log name         |
|--------------------|--------------------------|-----------------------|
| proof-io           | proof_io                 | proof_io              |
| ramfs              | ramfs                    | RAMFS                 |
| keyring            | keyring                  | KEYRING               |
| entropy            | entropy                  | ENTROPY               |
| crypto             | crypto                   | CRYPTO                |
| vfs                | vfs                      | VFS                   |
| market             | market                   | MARKET                |
| driver-virtio-rng  | driver_virtio_rng        | DRIVER-VIRTIO-RNG     |
| driver-virtio-gpu  | driver_virtio_gpu        | DRIVER-VIRTIO-GPU     |
| driver-ps2-input   | driver_ps2_input         | DRIVER-PS2-INPUT      |
| driver-virtio-blk  | driver_virtio_blk        | DRIVER-VIRTIO-BLK     |
| driver-virtio-net  | driver_virtio_net        | DRIVER-VIRTIO-NET     |
| driver-xhci        | driver_xhci              | DRIVER-XHCI           |
| driver-e1000       | driver_e1000             | DRIVER-E1000          |
| net-l2             | net_l2                   | NET-L2                |
| net-ip             | net_ip                   | NET-IP                |
| net-udp            | net_udp                  | NET-UDP               |
| net-dhcp           | net_dhcp                 | NET-DHCP              |
| input-router       | input_router             | INPUT-ROUTER          |
| compositor         | compositor               | COMPOSITOR            |
| wm                 | wm                       | WM                    |
| desktop-shell      | desktop_shell            | DESKTOP-SHELL         |
| image-codec        | image_codec              | IMAGE-CODEC           |
| clipboard          | clipboard                | CLIPBOARD             |
| login              | login                    | LOGIN                 |
| wallpaper          | wallpaper                | WALLPAPER             |
| toolkit            | toolkit                  | TOOLKIT               |
| about              | about                    | APP-ABOUT             |
| calculator         | calculator               | APP-CALCULATOR        |
| terminal           | terminal                 | APP-TERMINAL          |
| file-manager       | file_manager             | APP-FILE-MANAGER      |
| text-editor        | text_editor              | APP-TEXT-EDITOR       |
| settings           | settings                 | APP-SETTINGS          |
| process-manager    | process_manager          | APP-PROCESS-MANAGER   |

## Boot iterations

(populated by Task 10 onward — one section per boot attempt)
