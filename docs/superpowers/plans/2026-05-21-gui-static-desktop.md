# Static Desktop Bring-up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get a static NONOS desktop on screen under QEMU — wallpaper painted by the compositor's scanout plus desktop_shell chrome composited on top — by making the `driver_virtio_gpu` capsule observable, fixing whatever stage of its device bring-up is failing, and then walking the surface handshake up the chain (gpu → compositor → wallpaper → desktop_shell). No input wiring in this milestone.

**Architecture:** Diagnose-first, bottom-up. NONOS runs drivers as CPL=3 capsules; `driver_virtio_gpu` owns the virtio-gpu PCI device and serves a *primary scanout surface* over IPC on service `driver.virtio_gpu0`. The compositor looks that service up, pulls the surface, attaches it into its address space, and scans out. wallpaper + desktop_shell submit their own surfaces to the compositor. The current boot stalls because `driver_virtio_gpu` is **silent** (it lacks the Debug capability, so every `mk_debug` marker it emits is dropped) and its `setup::run()` is failing/looping invisibly — so the service never registers and everyone downstream parks. We make it observable first (Task 1), then fix the real failure the trace reveals (Task 2+), then verify each handshake hop up to a composited desktop.

**Tech Stack:** Rust nightly-2026-01-16 `#![no_std]` capsules on `x86_64-nonos-user`; virtio-gpu over MMIO + virtqueue DMA; NONOS capability model (`src/capabilities/types.rs`); `mk_debug`/`mk_service_lookup`/`mk_ipc_call` libc syscalls; `make nonos-mk-run` (QEMU `virtio-vga`) and `make nonos-mk-run-serial` (headless serial capture); the local trust ceremony (TA + 48 publisher seeds + sealed policy) already in place.

**Predecessor context:** `docs/superpowers/plans/2026-05-20-boot-handoff-context.md` (boot iteration log, the now-fixed trust bug), merge commit `22433110a`.

---

## Established ground truth (verified by reading the tree + boot logs)

- **32/32 capsules spawn + verify cleanly; 0 rejections; 0 trust-anchor failures; no faults.** The trust-verifier non-determinism is gone after main's memory/SMP refactor + in-house blake3. The graphics stall is a *userland bring-up* problem, not trust or paging.
- **`driver_virtio_gpu` is silent because it lacks Debug.** Debug = bit `0x100` (`src/capabilities/types.rs:63`). Capsules that DO print markers carry it (`wm`/`input_router` = `0x119`, `desktop_shell` = `0x1919`). `driver_virtio_gpu` caps:
  - Kernel-side spawn `src/hardware/virtio_gpu_capsule/spawn.rs:48-54` requests `IPC|Memory|Driver|DeviceEnum|Mmio|Irq|Dma` — **no Debug**.
  - Signed `userland/capsule_driver_virtio_gpu/Capsule.mk` `CAPSULE_REQUIRED_CAPS := 0x1F8018` — **no `0x100`**.
  - Its `main.rs::_start` calls `debug::marker(b"boot")` as the very first instruction and loops on `setup::run()` errors emitting `debug::marker(err)`, yet the boot log shows **zero** `[gfx.virtio_gpu0]` lines while its pid *does* enter user mode. ⇒ markers dropped, setup failing/looping unseen.
- **`setup::run()` stage order** (`userland/capsule_driver_virtio_gpu/src/setup/sequence.rs:30`): `find_virtio_gpu()` → `claim::claim()` → `mmio::grant()` → `irq::bind()` → `dma::map_queue()` → `init::bring_up()` → `seed_scanouts()` (`cmd::get_display_info`) → `primary_surface::create()` → return `Driver` → `server::run()`.
- **Compositor handshake** (`userland/compositor/src/setup/prime.rs`): `discover::lookup_gfx_endpoint()` (service `driver.virtio_gpu0`, `setup/discover.rs:19`) → `gfx_client::get_primary_surface(port, 1)` → checks `handle/width/height != 0` and `format == ARGB8888` → attach + damage; retried up to `READY_ATTEMPTS = 256` with `mk_yield()` between attempts, then `Err`.
- **wallpaper** (`userland/capsule_wallpaper/src/setup/prime.rs`): looks up `compositor` + `desktop_shell` services, `nonos_display_dimensions`, `mk_mmap` backing, `mk_surface_register` + `mk_surface_share`, `push_scene_submit`. **Needs the compositor service up.**
- **desktop_shell** (`userland/capsule_desktop_shell/src/setup/prime.rs`): similar; composites chrome through the compositor.
- **Uncommitted local work** that must be preserved/committed: compile fixes to `capsule_crypto`, `net_dns`, `net_sockets`, `net_nym`; the trust-ceremony seeds (`.keys/*.seed`, gitignored) + the regenerated `nonos-data` submodule artifacts (submodule working tree, not committed to the superproject).

## Scope check

One subsystem (graphics bring-up to a static composited desktop). One plan. Input, login, and app-launch are explicitly out of scope (separate milestones). The plan is a diagnose→fix loop; downstream tasks (3–5) carry explicit decision tables because their exact fix depends on what the Task-1 trace and each hop's instrumentation reveal — this is correct for hardware bring-up, not a placeholder.

## File structure

**Modified (capability enablement, Task 1):**
- `src/hardware/virtio_gpu_capsule/spawn.rs` — add `| Capability::Debug.bit()` to `requested_caps`.
- `userland/capsule_driver_virtio_gpu/Capsule.mk` — `CAPSULE_REQUIRED_CAPS := 0x1F8018` → `0x1F8118` (set Debug bit) + update the trailing comment.

**Modified (instrumentation, Tasks 2–5 — added then removed/quieted before milestone close):**
- `userland/capsule_driver_virtio_gpu/src/setup/sequence.rs` — per-stage `debug::marker` breadcrumbs.
- `userland/compositor/src/setup/prime.rs` — handshake breadcrumbs (gated to first few attempts to avoid 256× spam).
- `userland/capsule_wallpaper/src/setup/prime.rs`, `userland/capsule_desktop_shell/src/setup/prime.rs` — setup breadcrumbs.

**Verification artifacts (no commit):** `/tmp/gui-bootN.log` serial captures; QEMU screenshot via monitor `screendump`.

**Bring-up helper (run loop):** the `make nonos-mk-run-serial` capture + grep pattern is reused every task; defined once in Task 1 Step 4.

## Failure-mode reference — `driver_virtio_gpu setup::run()` stages

Keyed to the last `[gfx.virtio_gpu0]` marker seen (after Task 1 makes them visible). Each row: stage → file → most-likely cause → fix direction.

| Last marker / error | Stage + file | Likely cause | Fix direction |
|---|---|---|---|
| `virtio-gpu: device not found` | `discover::find_virtio_gpu` (`src/discover.rs`) | PCI enumeration via `mk_*` doesn't see vendor `0x1AF4` device `0x1050`; QEMU exposes `virtio-vga` (transitional id `0x1050`/legacy `0x1000`) | widen the accepted device-id set / check the PCI scan caps (`DeviceEnum`) |
| stalls after `claim`/no further | `claim::claim` (`src/setup/claim.rs`) | device-claim broker call rejects (Driver cap / epoch) | verify `Driver`+`DeviceEnum` granted; check claim broker return |
| stalls after MMIO grant | `mmio::grant` (`src/setup/mmio.rs`) | `map_device_memory` of the virtio BAR fails or wrong BAR | confirm `Mmio` cap + BAR index/size (echo the phys/len in a marker) |
| stalls after IRQ bind | `irq::bind` (`src/setup/irq.rs`) | MSI-X/INTx bind path (the `msix.rs` we just merged) returns error or never fires | check `Irq` cap; confirm the merged MSI-X `map_msix_window` succeeds; can stub IRQ to polling for first pixels |
| stalls in queue map | `dma::map_queue` (`src/setup/dma.rs`) | `Dma` cap / `mk_user_dma` mapping of the virtqueue rings fails | confirm `Dma` cap; echo device_addr + user_va |
| stalls in `bring_up` | `init::bring_up` (`src/init.rs`) | virtio feature negotiation / DRIVER_OK handshake; queue_size read 0 | echo status byte + queue_size; follow virtio 1.1 §3.1 init sequence |
| stalls in `get_display_info` | `cmd::get_display_info` (`src/device/cmd/…`) | control-queue submit/poll never completes (no IRQ + no poll fallback) | add a bounded busy-poll of the used-ring; this is the most probable deep spot |
| reaches `seed_scanouts` default | (no enabled scanout from host) | host reports 0 scanouts; falls back to 1024×768 | acceptable — proceed; primary_surface uses the default |
| stalls in `primary_surface::create` | `setup/primary_surface.rs` | resource-create / attach-backing / set-scanout command round-trip stalls | same poll-fallback fix as get_display_info |
| `setup complete` but compositor still loops | `server::run` / `get_primary_surface` handler | service not registered, or handler returns zeroed reply | Task 3 instruments the compositor side |

**Fallback trigger (Approach B):** if Tasks 2 spends >6 boot iterations stuck inside the virtqueue/DMA path (`get_display_info`/`primary_surface`) with no forward progress, switch the compositor to scan out the bootloader GOP framebuffer (handoff `fb`) for first pixels and file the virtio-gpu virtqueue work as a follow-up. Decision recorded in the context log, not taken silently.

---

## Task 0: Lock a clean, buildable baseline

The merge is committed (`22433110a`) but the WIP-capsule compile fixes are uncommitted. Commit them so every later boot starts from a known state and `git bisect` works.

**Files:**
- Modify (already edited, uncommitted): `userland/capsule_crypto/src/server/handlers/hkdf_sha256.rs`, `userland/capsule_net_dns/src/server/handlers/resolve_common.rs`, `userland/capsule_net_sockets/src/server/handlers/{getsockopt,setsockopt}.rs`, `userland/capsule_net_nym/src/server/handlers/*.rs`.

- [ ] **Step 1: Confirm the only uncommitted tracked changes are the compile fixes.**

```bash
cd /Users/abuhamzah/Dev/NONOS/nonos-kernel
git status --short | grep -vE '^\?\?| m nonos-data'
```
Expected: the crypto + net_dns + net_sockets + net_nym handler files only. (`m nonos-data` is the submodule working-tree state — leave it.)

- [ ] **Step 2: Commit the compile fixes.**

```bash
git add userland/capsule_crypto/src/server/handlers/hkdf_sha256.rs \
        userland/capsule_net_dns/src/server/handlers/resolve_common.rs \
        userland/capsule_net_sockets/src/server/handlers/getsockopt.rs \
        userland/capsule_net_sockets/src/server/handlers/setsockopt.rs \
        userland/capsule_net_nym/src/server/handlers
git commit -m "fix(userland): compile main's WIP net+crypto capsules

desktop-gui-prod requires net_dns/net_sockets/net_nym + capsule_crypto;
all had the same latent error class (respond()->i64 used where () is
expected; net_nym had 31 sites). Fixes are mechanical: discard the i64
or early-return after responding. Unblocks the GUI build."
```

- [ ] **Step 3: Record the trust-ceremony note.** The 48 publisher seeds live in `.keys/*.seed` (gitignored) and the regenerated cert/manifest/policy live in the `nonos-data` submodule working tree (not committed to the superproject). Add a one-line note so a fresh clone knows to re-run the ceremony.

```bash
cat >> docs/superpowers/plans/2026-05-20-boot-handoff-context.md <<'EOF'

## 2026-05-21: GUI bring-up baseline
Merge 22433110a committed. WIP capsule compile fixes committed. Trust
ceremony (TA + 48 publisher seeds + sealed policy) is local-only:
seeds in .keys/ (gitignored), artifacts in the nonos-data submodule
working tree. Re-run the ceremony on a fresh clone before building.
Starting static-desktop bring-up per 2026-05-21-gui-static-desktop.md.
EOF
git add docs/superpowers/plans/2026-05-20-boot-handoff-context.md
git commit -m "docs(boot-handoff): note GUI bring-up baseline + ceremony locality"
```

---

## Task 1: Make `driver_virtio_gpu` observable (grant Debug)

Without Debug the driver runs blind. Grant it in both the kernel spawn spec **and** the signed manifest, re-sign, rebuild, boot — and confirm `[gfx.virtio_gpu0]` lines now appear.

**Files:**
- Modify: `src/hardware/virtio_gpu_capsule/spawn.rs:48-54`
- Modify: `userland/capsule_driver_virtio_gpu/Capsule.mk` (the `CAPSULE_REQUIRED_CAPS` line)

- [ ] **Step 1: Add Debug to the kernel-side requested caps.**

In `src/hardware/virtio_gpu_capsule/spawn.rs`, extend the `requested_caps` expression:

```rust
        requested_caps: Capability::IPC.bit()
            | Capability::Memory.bit()
            | Capability::Debug.bit()
            | Capability::Driver.bit()
            | Capability::DeviceEnum.bit()
            | Capability::Mmio.bit()
            | Capability::Irq.bit()
            | Capability::Dma.bit(),
```

- [ ] **Step 2: Add Debug to the signed manifest caps.**

In `userland/capsule_driver_virtio_gpu/Capsule.mk`, change the required-caps line (Debug = `0x100`, so `0x1F8018 | 0x100 = 0x1F8118`):

```make
# CoreExec omitted by design; IPC|Memory|Debug|Driver|DeviceEnum|Mmio|Irq|Dma|Pio
CAPSULE_REQUIRED_CAPS    := 0x1F8118
```

- [ ] **Step 3: Re-sign the gpu capsule + rebuild kernel.**

```bash
cd /Users/abuhamzah/Dev/NONOS/nonos-kernel
make nonos-mk-driver-virtio-gpu-sign 2>&1 | tail -3
make nonos-mk-desktop-gui-prod 2>&1 | tail -4
```
Expected: cert+manifest re-written for `driver_virtio_gpu`; kernel builds clean.

- [ ] **Step 4: Boot + capture (this capture+grep recipe is reused every task).**

```bash
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 1
( timeout 150 make nonos-mk-run-serial > /tmp/gui-boot1.log 2>&1; echo "rc=$?" >> /tmp/gui-boot1.log )
echo "=== gfx markers now visible? ==="
grep -E '\[gfx\.virtio_gpu0\]' /tmp/gui-boot1.log | head -30
```
Expected: at minimum `[gfx.virtio_gpu0] boot`. If the driver is failing in setup you'll now ALSO see either a repeated error marker (e.g. `[gfx.virtio_gpu0] virtio-gpu: device not found`) or the last successful stage before silence — that is the Task-2 target.

- [ ] **Step 5: Confirm the hypothesis + commit the cap change.**

If `[gfx.virtio_gpu0] boot` appears → the missing-Debug hypothesis is proven and the driver was running blind. Commit:

```bash
git add src/hardware/virtio_gpu_capsule/spawn.rs userland/capsule_driver_virtio_gpu/Capsule.mk
git commit -m "feat(virtio_gpu): grant Debug capability for bring-up tracing

driver_virtio_gpu emitted zero [gfx.virtio_gpu0] markers despite its
pid running, because its caps (kernel spawn 0xF8018 / manifest
0x1F8018) lacked Debug (0x100). Every mk_debug was dropped, hiding a
failing setup::run(). Grant Debug in both the kernel spawn spec and
the signed manifest so the driver is observable."
```

If `boot` still does NOT appear even with Debug granted → the capsule's `_start` truly isn't running (spawn/scheduling/ELF-entry issue). Stop and pivot: inspect the kernel spawn path for `driver.virtio_gpu0` (does it reach `enter-user` for that pid, and at the ELF entry rip?). Record findings before proceeding.

---

## Task 2: Fix the failing `setup::run()` stage (trace-driven)

Add per-stage breadcrumbs so the *exact* failing stage is unambiguous, boot, then fix that one stage using the Failure-mode reference table.

**Files:**
- Modify: `userland/capsule_driver_virtio_gpu/src/setup/sequence.rs`

- [ ] **Step 1: Add stage breadcrumbs to `run()`.** Insert a marker before each stage so the last line printed pinpoints the stall. Replace the top of `pub fn run()`:

```rust
pub fn run() -> Result<Driver, &'static str> {
    debug::marker(b"stage: find");
    let dev = find_virtio_gpu().ok_or("virtio-gpu: device not found")?;
    debug::marker(b"stage: claim");
    let claim_epoch = claim::claim(dev.device_id)?;
    debug::marker(b"stage: mmio");
    let registers = mmio::grant(dev, claim_epoch)?;
    debug::marker(b"stage: irq");
    let irq = irq::bind(dev, claim_epoch, registers)?;
    debug::marker(b"stage: dma");
    let queue = dma::map_queue(dev.device_id, claim_epoch, registers, &irq)?;
    let regs = registers.regs(dev.pci_device);
    debug::marker(b"stage: bring_up");
    let init = bring_up(regs, queue.device_addr, dev.pci_device)?;
    if irq.grant_id != 0 {
        let _ = mk_irq_ack(irq.grant_id);
    }
    let layout = QueueLayout::new(init.queue_size, queue.user_va, queue.device_addr)?;
    let control_queue = ControlQueue::new(layout, regs);
    let scanouts = ScanoutTable::new();
    let fences = FenceCounter::new();
    let resources = ResourceTable::new();
    debug::marker(b"stage: display_info");
    seed_scanouts(&control_queue, &scanouts, &fences)?;
    debug::marker(b"stage: primary_surface");
    let primary = scanouts
        .get(0)
        .and_then(|s| s.enabled.then_some(s))
        .map(|s| {
            primary_surface::create(
                dev.device_id,
                claim_epoch,
                &control_queue,
                &fences,
                &resources,
                s,
            )
        })
        .transpose()?
        .flatten();
    debug::marker(b"stage: done");
    emit_claim_trace(regs, init.queue_size);
    Ok(Driver {
```
(Leave the rest of the function body unchanged.)

- [ ] **Step 2: Build + boot + read the last stage.**

```bash
make nonos-mk-driver-virtio-gpu 2>&1 | tail -2
make nonos-mk-desktop-gui-prod 2>&1 | tail -3 && make nonos-mk-esp 2>&1 | tail -2
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 1
( timeout 150 make nonos-mk-run-serial > /tmp/gui-boot2.log 2>&1; echo rc=$? >> /tmp/gui-boot2.log )
grep -E '\[gfx\.virtio_gpu0\] stage:' /tmp/gui-boot2.log | tail -5
grep -E '\[gfx\.virtio_gpu0\]' /tmp/gui-boot2.log | grep -v 'stage:' | tail -5
```
Expected: a `stage: …` ladder. The **last** `stage:` line before it stops (or before an error marker repeats) is the failing stage.

- [ ] **Step 3: Fix the failing stage** per the Failure-mode reference table. Make the SMALLEST change that advances one stage; add a value-echo marker if the cause is ambiguous (e.g. in `mmio::grant`, `debug::marker` the BAR phys+len). One stage per iteration — re-run Step 2 after each fix until `stage: done` and `[gfx.virtio_gpu0] setup complete` both appear.

- [ ] **Step 4: Confirm the service registers.** Once `setup complete` shows, confirm the driver answers the compositor by checking the kernel service registry log or adding a one-shot marker in `server::run` startup. Expected: no more compositor stall on lookup.

- [ ] **Step 5: Commit the driver fix(es).**

```bash
git add userland/capsule_driver_virtio_gpu/src/
git commit -m "fix(virtio_gpu): <exact stage fixed> so device bring-up completes

Trace (Task 2) showed setup::run() stalling at stage <X>. <one line on
the root cause + the fix>. Driver now reaches 'setup complete' and
registers driver.virtio_gpu0."
```

---

## Task 3: Verify the compositor ↔ gpu surface handshake

With the driver serving, confirm the compositor pulls + attaches the primary surface. Instrument only if it still stalls.

**Files:**
- Modify (if needed): `userland/compositor/src/setup/prime.rs`

- [ ] **Step 1: Boot + check for compositor progress.**

```bash
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 1
( timeout 150 make nonos-mk-run-serial > /tmp/gui-boot3.log 2>&1; echo rc=$? >> /tmp/gui-boot3.log )
grep -iE '\[compositor\]|setup complete|scanout|attach' /tmp/gui-boot3.log | head
```
Expected ideally: a `[compositor] setup complete` (compositor has no Debug marker today — see Step 2 if silent).

- [ ] **Step 2: If the compositor is silent, confirm it has Debug + add breadcrumbs.** Compositor caps are `0x7919` which **includes** Debug (`0x100`), so markers should work. Add breadcrumbs in `prime.rs::run_once` around the handshake:

```rust
    let gfx = discover::lookup_gfx_endpoint()?;
    crate::debug::marker(b"gfx endpoint found");
    let primary = gfx_client::get_primary_surface(gfx.port, 1)?;
    crate::debug::marker(b"primary reply received");
    if primary.handle == 0 || primary.width == 0 || primary.height == 0 {
        return Err("gfx primary surface absent");
    }
```
(Use the compositor's existing `debug` module; if it lacks a `marker` helper, mirror the wallpaper/desktop_shell `debug.rs` pattern in one small file.)

- [ ] **Step 3: Build + boot + classify.**

```bash
make nonos-mk-compositor 2>&1 | tail -2
make nonos-mk-desktop-gui-prod 2>&1 | tail -2 && make nonos-mk-esp 2>&1 | tail -2
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 1
( timeout 150 make nonos-mk-run-serial > /tmp/gui-boot3b.log 2>&1; echo rc=$? >> /tmp/gui-boot3b.log )
grep -iE '\[compositor\]|gfx endpoint|primary reply|setup complete' /tmp/gui-boot3b.log | head
```
Decision:
- No `gfx endpoint found` → service still not registered → back to Task 2 Step 4.
- `gfx endpoint found` but no `primary reply received` → the `get_primary_surface` IPC round-trip stalls → instrument the gpu `server/handlers/get_primary_surface.rs` to confirm it receives the request and returns a non-zero reply.
- `primary reply received` then `gfx primary surface absent` → the driver returns a zeroed/!ARGB8888 surface → fix the handler's reply fields / surface format.
- `[compositor] setup complete` → handshake works; proceed to Task 4.

- [ ] **Step 4: Commit whatever fix landed** (`git add` the touched gpu/compositor files; message names the exact handshake bug).

---

## Task 4: First pixels — compositor scanout + wallpaper paint

**Files:**
- Modify (if needed): `userland/compositor/src/gfx_client/set_scanout.rs`, `userland/capsule_wallpaper/src/setup/prime.rs`

- [ ] **Step 1: Boot graphically + screendump.** Use the graphical target so the framebuffer is real, and capture a screenshot via the QEMU monitor.

```bash
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 1
make nonos-mk-run > /tmp/gui-boot4.log 2>&1 &
QPID=$!
sleep 60
# QEMU monitor is multiplexed on stdio (-serial mon:stdio); capture the framebuffer:
# (if a monitor socket is configured use it; else observe the QEMU window directly)
grep -iE '\[wallpaper\]|scene_submit|scanout|present|setup complete' /tmp/gui-boot4.log | head
kill $QPID 2>/dev/null
```
Expected: `[wallpaper] setup complete` (or its equivalent) and a non-black QEMU window filled with the wallpaper's `DEFAULT_ARGB` (0xFF101620 dark blue-grey).

- [ ] **Step 2: If the screen is black but wallpaper completed setup**, the compositor isn't scanning out the wallpaper surface. Verify the scanout path: `compositor` must `set_scanout` the resource and `flush`/`transfer_to_host` so the host displays it. Instrument `gfx_client/set_scanout.rs` + `flush.rs` with markers and confirm they run and succeed.

- [ ] **Step 3: If wallpaper setup fails** (`[wallpaper] setup failed`), read which step: `discover` (compositor/desktop_shell service), `nonos_display_dimensions` (rc!=0), `mk_mmap` (null), `mk_surface_register` (sid<0), `mk_surface_share` (handle<=0), or `push_scene_submit`. Fix that step (likely `nonos_display_dimensions` returning 0 if the gpu didn't publish a mode, or the surface syscalls needing the GraphicsSurface* caps — wallpaper's caps must include them).

- [ ] **Step 4: Iterate to a painted wallpaper.** Re-run Step 1 after each fix. **Milestone checkpoint: the QEMU window shows the wallpaper colour** = first pixels proven.

- [ ] **Step 5: Commit.**

```bash
git add userland/compositor/src userland/capsule_wallpaper/src
git commit -m "fix(gfx): compositor scans out wallpaper surface — first pixels

<one line on the scanout/wallpaper bug fixed>. QEMU window now paints
the wallpaper background through the virtio-gpu primary surface."
```

---

## Task 5: Composite desktop_shell chrome (static desktop milestone)

**Files:**
- Modify (if needed): `userland/capsule_desktop_shell/src/setup/prime.rs` and its render/compositor-client modules

- [ ] **Step 1: Boot + check desktop_shell.**

```bash
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 1
make nonos-mk-run > /tmp/gui-boot5.log 2>&1 &
QPID=$!; sleep 60
grep -iE '\[desktop_shell\]|overlay attached|setup complete|setup failed' /tmp/gui-boot5.log | head
kill $QPID 2>/dev/null
```
Expected: `[desktop_shell] overlay attached` + chrome drawn over the wallpaper in the QEMU window.

- [ ] **Step 2: If desktop_shell setup fails**, classify the same way as wallpaper (it shares the discover/surface pattern) and fix. It composites *on top of* the wallpaper, so it needs the compositor's multi-surface z-order to work — confirm the compositor honours the submitted `z` and composites both surfaces.

- [ ] **Step 3: Visual verification — the milestone.** The QEMU window shows wallpaper **plus** desktop_shell chrome (dock/menubar/whatever it draws). No input needed. This is "static desktop" = done.

- [ ] **Step 4: Capture proof + commit.**

```bash
git add userland/capsule_desktop_shell/src userland/compositor/src
git commit -m "feat(gui): static desktop renders — wallpaper + desktop_shell chrome

<one line on the desktop_shell/compositor compositing fix>. Static
desktop milestone: compositor scans out the wallpaper and composites
desktop_shell chrome on top via the virtio-gpu primary surface."
```

---

## Task 6: Quiet the instrumentation + record the result

Bring-up breadcrumbs were diagnostic scaffolding. Keep the high-value ones, drop the noise, record the outcome.

**Files:**
- Modify: the four instrumented files (`setup/sequence.rs`, compositor/wallpaper/desktop_shell `prime.rs`)
- Modify: `docs/superpowers/plans/2026-05-20-boot-handoff-context.md`

- [ ] **Step 1: Keep one breadcrumb per capsule (`boot` + `setup complete`), remove the per-stage spam** added in Task 2 Step 1 and Task 3 Step 2, so steady-state serial isn't flooded. Leave the Failure-mode table's stage markers behind a `#[cfg(feature = "gfx-trace")]` gate if you want them re-armable.

- [ ] **Step 2: Decide whether `driver_virtio_gpu` keeps Debug.** For ongoing GUI work, keep it. If a production/no-debug posture is wanted later, gate it — note the decision; do not silently revert (that re-blinds the driver).

- [ ] **Step 3: Build + one clean confirmation boot.**

```bash
make nonos-mk-desktop-gui-prod 2>&1 | tail -2 && make nonos-mk-esp 2>&1 | tail -2
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 1
( timeout 120 make nonos-mk-run-serial > /tmp/gui-final.log 2>&1; echo rc=$? >> /tmp/gui-final.log )
echo "spawned: $(grep -c 'capsule spawned' /tmp/gui-final.log)  rejected: $(grep -c 'manifest rejected' /tmp/gui-final.log)"
grep -iE 'setup complete|overlay attached' /tmp/gui-final.log | head
```
Expected: 32 spawned / 0 rejected, gpu+compositor+wallpaper+desktop_shell all report setup complete.

- [ ] **Step 4: Record the result + commit.**

```bash
cat >> docs/superpowers/plans/2026-05-20-boot-handoff-context.md <<'EOF'

## 2026-05-21: Static desktop reached
virtio_gpu bring-up fixed (Debug cap + <stage fix>); compositor↔gpu
handshake verified; wallpaper paints; desktop_shell composites chrome.
QEMU shows a static desktop. Input/login/apps are the next milestones.
EOF
git add docs/superpowers/plans/2026-05-20-boot-handoff-context.md userland/
git commit -m "chore(gui): quiet bring-up tracing; record static-desktop milestone"
```

- [ ] **Step 5: Push.**

```bash
git push
```

---

## Self-review against the spec/goal

- **Goal (static desktop)** → Tasks 4 (wallpaper/first pixels) + 5 (desktop_shell chrome) deliver it; 1–3 are the prerequisite driver+handshake bring-up.
- **Diagnose-first (Approach A)** → Task 1 makes the driver observable before any fix; Task 2 fixes the trace-identified stage; Tasks 3–5 each instrument-then-fix one hop.
- **Fallback (Approach B)** → explicit trigger in the Failure-mode section (>6 stuck iterations in the virtqueue/DMA path → bootloader GOP fb), recorded not silent.
- **Capability root cause** → Task 1 grants Debug in both the kernel spawn spec and the signed manifest (both verified missing it).
- **Placeholder scan** → no TBDs; every code step shows the exact edit; every boot step shows the command + expected grep output. The `<exact stage fixed>` / `<one line on…>` tokens in commit messages are intentional fill-ins keyed to whatever the trace reveals, not skipped work.
- **Type/name consistency** → `debug::marker(&[u8])` (the gpu capsule's existing helper, prefix `[gfx.virtio_gpu0]`), `Capability::Debug.bit()` = 256/0x100, service name `driver.virtio_gpu0`, `READY_ATTEMPTS=256` — all match the read sources.
- **Out of scope honored** → no input/login/app-launch tasks; net stack only touched in Task 0 to make the build compile.
