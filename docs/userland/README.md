# Userland

Every program NONOS runs outside the kernel runs in ring 3, as a [capsule](../overview/glossary.md#capsule) or as a Linux [guest](../overview/glossary.md#guest) of one; this section says what a capsule is, how one goes from source to a running process, and how to write and ship your own.

## Pages in this section

- [Writing an app](writing-an-app.md): a windowed app on `nonos_app_skeleton`, and its host tests, step by step on `capsule_hello`.
- [Shipping an app](shipping-an-app.md): from the crate to a signed image and a tile on the dock and in the Launchpad.
- [Manifests and capabilities](manifests-and-capabilities.md): the manifest format and how the capability word is fixed.
- [Signing and publisher keys](signing-and-publisher-keys.md): `capsule-sign`, the keys, the enrollment and the market's publishers.
- [libc and the Rust runtimes](libc.md): `nonos_libc`, `nonos_runtime`, the SDK, the toolkit and `std`.
- [IPC services](ipc-services.md): service names, ports and message formats.
- [Design system](design-system/README.md): shared theme colours and widgets for app screens (proposed).
- [The Linux personality](linux-personality.md): which Linux calls are served, which are refused, and why.

## What a capsule is

A capsule is an ELF and three files that vouch for it, and the kernel reads the four together. The build writes the three into `nonos-data/trust/capsules/` as `<bin>.nonos_id_cert.bin`, `<bin>.manifest.bin` and `<bin>.zk_trailer.bin` (`nonos-mk/capsule.mk:101-103`, `CAPSULE_BIN_NAME`).

- The ELF is a static, position independent executable for the `x86_64-nonos-user` target, whose `vendor` is `nonos` and whose linker runs with `-nostdlib -pie` (`userland/x86_64-nonos-user.json:4-33`).
- The [NONOS ID certificate](../overview/glossary.md#nonos-id-certificate) names the [publisher](../overview/glossary.md#publisher)'s two public keys, the namespaces the publisher may sign for and a ceiling on capabilities.
- The [manifest](../overview/glossary.md#manifest) binds the BLAKE3 hash of the ELF, its namespace, its IPC endpoints and the capabilities it asks for, signed by the publisher.
- The [attestation trailer](../overview/glossary.md#attestation-trailer) comes from one STARK [enrollment](../overview/glossary.md#enrollment) of the whole capsule set.

The kernel does not take a capsule's word for anything. It computes a [capability word](../overview/glossary.md#capability-word) from the verified manifest. Every system call the kernel knows passes a gate, most of them a bit in that word, and every IPC send is checked against it. [Manifests and capabilities](manifests-and-capabilities.md) has the rules.

## From source to a running process

```mermaid
flowchart LR
  A[Capsule.mk] --> B[cargo build]
  B --> C[capsule-sign]
  C --> D[STARK enrollment]
  D --> E[kernel image]
  D --> F[file store]
  E --> G[spawn gate]
  F --> G
  G --> H[running process]
```

1. Declare. A capsule is declared once, in its `Capsule.mk`: slug, binary name, crate directory, handle, domain, namespace, service and reply endpoints and required capabilities, followed by an include of the shared template. The template stops the build when any of those is missing (`nonos-mk/capsule.mk:28-54`, `CAPSULE_REQUIRED_CAPS`). [Shipping an app](shipping-an-app.md) goes through every step for one app.
2. Build. The template runs `cargo build --release` for the target with `-Zbuild-std` (`nonos-mk/capsule.mk:186-198`, `USERLAND_LIBC`), building core and alloc unless `CAPSULE_BUILD_STD` names more (`nonos-mk/capsule.mk:83`, `CAPSULE_BUILD_STD`). A capsule made from an unmodified crates.io program is built by its own rule in `mk/20-build.mk` and copied in (`nonos-mk/capsule.mk:92`, `CAPSULE_PREBUILT_BIN`).
3. Sign. The host tool `capsule-sign` issues the certificate under the [trust anchor](../overview/glossary.md#trust-anchor) and signs the manifest with the publisher's Ed25519 and ML-DSA-65 keys (`nonos-mk/capsule.mk:252-297`, `CAPSULE_SIGN_BIN`). [Signing and publisher keys](signing-and-publisher-keys.md) walks through it.
4. Enroll. One run of `nonos-stark-enroll` measures every capsule and writes the [policy root](../overview/glossary.md#policy-root) and one trailer per capsule (`mk/20-build.mk:600-605`, `NONOS_STARK_ENROLL`).
5. Ship. A capsule the kernel starts by itself is compiled into the kernel image by its [kernel mirror](../overview/glossary.md#kernel-mirror), for example `PROOF_IO_ELF` in `src/userspace/capsule_proof_io/embed.rs:17-35`. A capsule installed later is read from the [file store](../overview/glossary.md#file-store) by the installer and reaches the kernel through `sys_capsule_load` (`src/syscall/microkernel/capsule_load/handle.rs:29-34`).
6. Admit. The [spawn gate](../overview/glossary.md#spawn-gate), `spawn_verified_as`, checks the [boot profile](../overview/glossary.md#boot-profile), then verifies the certificate, the manifest and its signatures, the ELF hash, the target, the endpoints, the capability grant and the trailer (`src/kernel_core/process_spawn/capsule_spawn/runner/verified.rs:38-63`).
7. Spawn. `finish` claims the [reply inbox](../overview/glossary.md#reply-inbox), loads the ELF, installs the capability word, allocates the stacks, registers the service [endpoint](../overview/glossary.md#endpoint) and puts the process on the run queue (`src/kernel_core/process_spawn/capsule_spawn/runner/install/install.rs:88-117`).

A failure at any step stops that capsule and nothing else. A process that fails half way through step 7 is torn down with exit status -1 (`src/kernel_core/process_spawn/capsule_spawn/runner/install/install.rs:79-80`, `SPAWN_FAILED`).

## What lives under userland/

These counts were taken on this tree by listing the top-level directories of `userland/` and the files they hold.

| Kind | How it is recognised | Count |
|---|---|---|
| Directories | top level of `userland/` | 288 |
| Crates | a top-level directory with a `Cargo.toml` | 271 |
| Capsule declarations | a directory with a `Capsule.mk` | 107 |
| Capsules the build includes | an include line in `mk/20-build.mk` | 97 |
| Driver capsules the build includes | `capsule_driver_*` among the 97 | 18 |
| Proof crates | a name ending in `_proofs` | 107 |
| Other crates | a `Cargo.toml`, neither of the two above | 67 |
| Linux userland programs | declared in `userland/linux_userland/Userland.mk` | 19 |

What the numbers hide:

- The include block runs from `capsule_proof_io` to `capsule_power` (`mk/20-build.mk:463-562`). Ten declared capsules are outside it, so this release does not build, sign or enroll them: `capsule_attack`, `capsule_smp_stress` and eight drivers, `capsule_driver_ax88179`, `capsule_driver_cdc_ecm`, `capsule_driver_cdc_ncm`, `capsule_driver_e1000e`, `capsule_driver_igc`, `capsule_driver_rndis`, `capsule_driver_rtl8153` and `capsule_driver_rtsx`. The block holds 98 include lines, not 97: one, behind a `wildcard` guard, names `capsule_flacprobe`, which is not in this tree (`mk/20-build.mk:467-469`, `capsule_flacprobe`).
- One included capsule, `shield-vectors`, is a development test: only a [development image](../overview/glossary.md#development-image) signs and enrolls it (`nonos-mk/capsule.mk:163-170`, `NONOS_DEV_CAPSULES`).
- Seven proof crates carry a `capsule_` prefix, `capsule_linux_proofs` among them. They are host test crates, not capsules.
- Of the 67 other crates, 65 have a `src/lib.rs`. The two that do not, `capsule_driver_bga` and `capsule_gui_proof`, are capsule programs that no `Capsule.mk` declares, so they are not built into any image. Two of the libraries are test support: `linux_guests` also builds the test guests a test image enrolls (`mk/20-build.mk:568-571`, `NONOS_LINUX_GUESTS`), and `i2c_proofs_libc_shim` exists for the I2C proof crates.
- Seventeen directories have no `Cargo.toml`. Ten are capsules whose program is built elsewhere with `std`: `ripgrep`, installed from crates.io at a pinned version (`mk/20-build.mk:279-290`, `UPSTREAM_RIPGREP_VERSION`), and `sd`, the seven tool apps below and the `tokio-smoke` test, built from source in `userland/upstream-src/`. The other seven are `assets`, `linux_userland`, `nonos_examples`, `platform`, `sdk`, `upstream-src` and `vendor`. The `sdk` and `nonos_examples` directories hold crates one level down.

The build catalogue, `tools/nix/capsules.json`, lists 116 programs: the 97 included capsules and the 19 Linux userland programs (`mk/60-nix.mk:42`, `NONOS_CATALOGUE_CAPSULES`).

## The capsules by role

Grouped by the first word of their service name in the catalogue:

| Service name | Count | Examples |
|---|---|---|
| `app.*` | 29 | `app.terminal`, `app.settings`, `app.browser`, `app.linux` |
| `driver.*` | 18 | `driver.nvme0`, `driver.rtl8821ce0`, `driver.hda0` |
| `net.*` | 12 | `net.core`, `net.sockets`, `net.nym`, `net.anon` |
| `tool.*` | 11 | `tool.ripgrep`, `tool.grex`, `tool.model-fetch` |
| anything else | 27 | `vfs_pool`, `keyring`, `policy`, `compositor`, `wm` |

The system services a capsule talks to are on [IPC services](ipc-services.md). The drivers have their own section, starting at [the driver model](../drivers/README.md).

## Installed tool apps

`userland/apps.list` names the crates.io tools installed as capsules, one line per app in the form `slug bin service_port reply_port` (`userland/apps.list:1`, `service_port`).

| App | Service port | Reply port |
|---|---|---|
| `grex` | 4900 | 4901 |
| `dotenv-linter` | 4902 | 4903 |
| `pastel` | 4904 | 4905 |
| `jsonxf` | 4906 | 4907 |
| `tokei` | 4910 | 4911 |
| `huniq` | 4912 | 4913 |
| `csview` | 4914 | 4915 |

All seven are built from unmodified crates.io source by one rule (`mk/20-build.mk:342`, `NONOS_TOOL_BINS`). Each is spawned with CoreExec, IPC, Memory and FileSystem and nothing else (`src/userspace/tool_capsules/spec.rs:42-45`, `SANDBOX_CAPS`). Two more tool capsules, `tool.ripgrep` on 4820 and `tool.sd` on 4822, are also unmodified crates.io programs but are not in the list. The maintainer script `tools/nonos-app` adds a tool: it makes the tool's publisher keys with `capsule-sign keygen` (`tools/nonos-app:145`, `keygen`), appends a line to the list (`tools/nonos-app:284`, `APPS`) and rewrites the kernel's tool registry (`tools/nonos-app:206`, `REGISTRY`). [Writing an app](writing-an-app.md#choose-the-right-path-first) says when a program belongs here and when it needs a window of its own.

## Runtimes

Most capsules are `no_std` programs on `nonos_libc`, the userland side of the kernel ABI. Seventeen are Rust programs that use `std` through the NONOS platform layer in `toolchain/nonos-std/`. A second native runtime and an SDK are in the tree, but no capsule in this release uses them. [libc and the Rust runtimes](libc.md) says what each one does and does not do.

Unmodified Linux programs run as guests of the [Linux personality](../overview/glossary.md#linux-personality), a capsule that answers their system calls, and never as capsules themselves, even the nineteen that are signed and enrolled like capsules. See [The Linux personality](linux-personality.md).

## See also

- [Architecture in one diagram](../overview/architecture.md)
- [Processes and capsule spawn](../kernel/processes-and-spawn.md)
- [Capsule isolation](../security/capsule-isolation.md)
- [Writing a driver](../drivers/writing-a-driver.md)
- [Tests and proofs](../contributing/tests-and-proofs.md)
