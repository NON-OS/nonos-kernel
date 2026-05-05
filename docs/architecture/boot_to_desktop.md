# Boot to desktop

End-to-end path from bootloader to a running desktop. The kernel
sets up primitives, spawns init, and disappears. Init brings up the
capsule graph that runs the desktop.

```
bootloader
     |
     |  BootHandoffV1
     v
+--------------------+
| init_handoff       |   validate magic, version, ranges
+--------------------+
     |
     v
+--------------------+
| microkernel_init   |   memory, log, firmware, RNG,
|                    |   IPC MAC, caps, scheduler, clock,
|                    |   proc table, VM, ELF loader, keys
+--------------------+
     |
     v
+--------------------+
| microkernel_main   |   create init pid + address space
+--------------------+
     |
     v   CPL=3
+----------------------------------------------------+
|  init: spawn capsule graph                         |
+----------------------------------------------------+
     |
     +-- primitives  : entropy, keyring, ramfs, vfs, crypto
     +-- desktop     : input, display, compositor, shell, wallpaper
     +-- system apps : market, wallet
     +-- user apps   : terminal, filemanager, browser, settings
```

## 1. Bootloader handoff

The bootloader passes a `BootHandoffV1` describing:

- physical memory map
- framebuffer layout (base, pitch, width, height, format)
- boot entropy (32 bytes minimum, mixed into RNG seed)
- kernel image measurement (BLAKE3 over the loaded kernel)
- optional capsule bundle region (signed bundle pre-loaded by the
  bootloader so userland can come up without a network)

`init_handoff` validates magic, version, struct size, pointer
ranges, and alignment. A bad handoff routes to the early recovery
console.

## 2. Kernel init

`microkernel_init` runs in this order:

1. arch memory map walk + framebuffer record (no rendering yet)
2. boot log binds to serial and to the framebuffer record
3. firmware tables (ACPI/SMBIOS on x86_64; DTB on aarch64/riscv64)
4. settings + hostname
5. RNG init (fatal if it fails)
6. IPC MAC key seeded from RNG (fatal if it fails)
7. capability table for the init process
8. scheduler
9. clock
10. process table
11. unified VM (fatal if it fails)
12. ELF loader
13. kernel keys

After this point the kernel does not touch input, display, or any
app policy. `microkernel_main` creates the init process, gives it
its own address space, and transfers control.

## 3. Init capsule graph

Init spawns the system capsules in dependency order. Each spawn is
a real ELF load, a real address space, a real cap mask, and a real
endpoint registration:

```
1.  capsule_entropy        provides random bytes to other capsules
2.  capsule_keyring        publisher and signing key custody
3.  capsule_ramfs          RAM-only filesystem for in-flight blobs
4.  capsule_vfs            unified filesystem broker over ramfs and persistent stores
5.  capsule_crypto         hash, KDF, AEAD, signing for app capsules
6.  capsule_input          owns the kernel input handoff
7.  capsule_display        owns the framebuffer handoff
8.  capsule_compositor     consumes display + input, owns surfaces, z-order, damage
9.  capsule_shell          desktop shell, launcher, dock, status area
10. capsule_wallpaper      wallpaper surface, drawn first under all app surfaces
11. capsule_market         marketplace UI
12. capsule_wallet         wallet identity and signing
13. capsule_terminal       terminal frontend
14. capsule_filemanager    file manager UI
15. capsule_browser        browser shell
16. capsule_settings       desktop settings UI
```

A failed spawn keeps the ones that came before; the failed capsule
appears `Dead` in `services::lifecycle`, and any IPC client gets
`ESTALE` until it is respawned by `capsule_update` or by the user.

## 4. What the kernel does not do at boot

- no compositor
- no shell
- no wallpaper rendering
- no font rendering
- no theme system
- no notifications
- no app policy
- no marketplace logic
- no wallet code
- no browser

Everything visible after boot lives above the syscall boundary.

## 5. Recovery console

If `microkernel_init` halts (handoff invalid, RNG failed, VM init
failed, IPC seed failed), the kernel writes a serial trace and
loops. The recovery console is serial-only. There is no graphical
fallback in the kernel, by design.

## 6. Per-arch boot tail

Per-arch boot code lives under `src/arch/<arch>/boot/init`. The
shared `microkernel_init` is arch-agnostic; the arch tail handles
GDT/IDT/TSS on x86_64, MMU on aarch64, and PLIC/CLINT on riscv64.
The capsule graph above is identical across arches once the per-arch
tail finishes.
