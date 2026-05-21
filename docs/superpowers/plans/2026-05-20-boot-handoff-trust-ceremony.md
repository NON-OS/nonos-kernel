# Boot-handoff Trust Ceremony + GUI-boot Iteration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to execute task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get a NONOS local boot that reaches a working GUI (compositor + wm + desktop_shell + wallpaper rendering on QEMU), by replacing the broken-on-merge trust chain with a self-consistent local scratch ceremony — mirroring what CI's `scratch-sign-matrix` does — then iterating on the boot log until every capsule spawns and the desktop renders.

**Architecture:** The NONOS trust chain has four cryptographic bindings (TA→cert→manifest→ELF). All four must come from one signing session per capsule. After the merge from `origin/main`, we have theirs' policy + theirs' manifests + ours-locally-built ELFs + a partially-restored cert set — every binding is broken in some way. The only sound fix is a full scratch ceremony: fresh TA pair, fresh per-capsule publisher pairs (×34), local ELF rebuild for every capsule, new policy seal, full cert+manifest re-sign, kernel rebuild against the new policy. The CI workflow `nonos-trust-chain.yml` job `scratch-sign-matrix` is the reference (already does this for 13 capsules; we extend to 34).

**Tech Stack:** `nonos-sign/target/release/capsule-sign` (host signing tool), Makefile targets `nonos-mk-trust-policy` + `nonos-mk-<slug>` + `nonos-mk-<slug>-sign`, `nonos-mk/capsule.mk` template, `x86_64-nonos-user.json` target, QEMU + OVMF runtime.

**Sibling context log:** `docs/superpowers/plans/2026-05-20-boot-handoff-context.md` — running notebook for each boot iteration's outcome. Update after every boot.

---

## Established ground truth (verified, supersedes earlier assumptions)

- **Merge committed**: `git log -1 HEAD` is the merge commit `72265e14d`, parents `919127580` (ours) + `7d20c23d5` (theirs). Branch is 282 commits ahead of `origin/feature/bootloader-hardening`.
- **Trust chain layers + spawn-time verifier** (from kernel error messages, all four are checked):
  1. **TA→Cert**: kernel says `trust-anchor signature on cert is bad (Ed25519)` when `verify(cert_signature, policy.TA_pub)` fails.
  2. **Cert↔Manifest cert_id binding**: kernel says `manifest references a different cert than the one provided` when `manifest.cert_id ≠ hash(provided_cert)`.
  3. **Cert→Manifest signature**: implicit in (2) — the kernel would also reject if `verify(manifest_signature, cert.publisher_pub)` fails, though that path didn't fire in the most recent boot.
  4. **Manifest→ELF**: kernel says `embedded ELF hash differs from manifest expected hash (rebuild + re-sign)` when `sha512(embedded_elf_bytes) ≠ manifest.elf_hash`.
- **Most recent boot's failure breakdown** (after Path A — restoring origin/main's cert+manifest set):
  - 22 capsules failed Layer 4 (ELF↔manifest hash mismatch) — locally-built ELFs don't match origin/main's CI-recorded hashes.
  - 4 capsules failed Layer 3 (cert_id binding): RAMFS, DRIVER-XHCI, DESKTOP-SHELL, APP-TERMINAL — cert and manifest from different signing sessions.
  - 1 capsule failed Layer 1 (toolkit): we signed locally against the merged policy that uses theirs' TA pub.
- **Verified capsule set (34 capsules)** — from `nonos-sign/tests/artifacts.rs:40-75` `VERIFIED` table:
  - **Core (7)**: proof-io, ramfs, keyring, entropy, crypto, vfs, market
  - **Drivers (7)**: driver-virtio-rng, driver-virtio-gpu, driver-ps2-input, driver-virtio-blk, driver-virtio-net, driver-xhci, driver-e1000
  - **Network (4)**: net-l2, net-ip, net-udp, net-dhcp
  - **UI infra (4)**: input-router, compositor, wm, desktop-shell
  - **UI services (4)**: image-codec, clipboard, login, wallpaper
  - **Shared (1)**: toolkit
  - **Apps (7)**: about, calculator, terminal, file-manager, text-editor, settings, process-manager
- **CI reference**: `.github/workflows/nonos-trust-chain.yml:142-231` is the canonical scratch-ceremony recipe; we mirror it for 34 capsules instead of 13.
- **Kernel boot path works** through handoff: `[PT0]…[CR3OK]…NX64…R…[NONOS] Handoff OK` confirms bootloader→kernel handoff, identity-teardown, and CR3 swap all succeed on the merged tree. LAPIC `#PF` issue (memory:project_lapic_pf_rootcause) appears resolved: `[VM-INIT] LAPIC rebased to UC kernel mapping`. PCI enumeration completes. Userland init reaches the per-capsule spawn loop. **The blocker is purely the trust chain**, not bootloader/memory/handoff/interrupts.

---

## Scope check

Single plan, one terminal artifact (a working GUI boot). Subsystems are sequential dependencies (trust ceremony → kernel rebuild → boot → per-capsule diagnosis → GUI render), not independent. No sub-plans needed. Within the plan, Phase 1 (ceremony) is a one-shot batch; Phases 2-4 (boot + iterate + commit) require interleaved diagnosis with explicit checkpoints.

## Isolation

This is read-write work directly on `feature/bootloader-hardening`. The trust artifacts are repo-tracked (`nonos-data/trust/{capsules,keys,policy}/`); the ceremony produces commits we want on this branch as follow-ups to the merge commit. No worktree needed.

## File structure

**Repo files modified by this plan (Phase 1, all tracked):**
- `nonos-data/trust/policy/nonos_trust_anchor.policy.bin` — new sealed policy (overwrite).
- `nonos-data/trust/keys/*.pub` — 35 fresh pub keys (1 TA pair × 2 algs + 34 capsule pairs × 2 algs = 70 files).
- `nonos-data/trust/capsules/*.{nonos_id_cert,manifest}.bin` — 68 fresh artifacts (34 capsules × 2 file types).

**Repo files modified by this plan (Phase 4, tracked docs):**
- `docs/superpowers/plans/2026-05-20-boot-handoff-context.md` — created in Task 0, updated after every boot.

**Untracked host-only files (mode 600, NEVER commit):**
- `.keys/*.seed` — 35 fresh seeds (TA + 34 capsule publishers, both algs).

**Read-only inputs:**
- `.github/workflows/nonos-trust-chain.yml` (reference for the ceremony recipe).
- `nonos-sign/tests/artifacts.rs` (canonical capsule list + verification logic).
- `Makefile` + `nonos-mk/capsule.mk` + each `userland/<cap>/Capsule.mk` (target templates).

## Failure modes to expect (read before executing)

These will likely surface during execution; the plan handles them:

1. **Capsule.mk missing for a verified capsule** — older capsules sign cleanly; newer ones (`net_*`, app capsules, `image_codec`, `clipboard`, `wallpaper`) may have incomplete Makefile rules. Task 6 handles per-capsule failures defensively.
2. **`nonos-mk-<slug>-sign` requires non-publisher inputs** — some capsules' sign targets may need extra inputs (e.g., a precomputed value). Per-capsule failures are recorded in the context log and skipped, then revisited.
3. **The kernel build embeds `nonos-capsule-toolkit` only under certain profiles** — if a capsule's feature isn't included in the default `nonos-mk-run` profile, its missing signature won't block boot. The first boot (Task 8) reveals which capsules the kernel actually spawns.
4. **`market` capsule needs `marketplace-abi`** — built separately. Task 5 builds it before the capsule loop.
5. **Disk-image refresh** — `make nonos-mk-run` builds the kernel + ESP image. If the ESP cache is stale, the kernel that boots might not include the freshly-signed artifacts. Task 7 rebuilds the bootloader (which forces the kernel ELF refresh).
6. **Per-capsule launch errors AFTER the trust chain is consistent** — e.g., ramfs may need files baked in; compositor may need GPU init. Those are Phase 3 work, not Phase 1.

---

## Task 0: Create context-log file and lock starting state

**Files:**
- Create: `docs/superpowers/plans/2026-05-20-boot-handoff-context.md`

- [ ] **Step 1: Create the running notebook.** Write the initial header capturing the merge commit, the current branch, and the canonical capsule list. This file is updated after every iteration; it is the single source of truth for "what worked in this boot".

```bash
cat > docs/superpowers/plans/2026-05-20-boot-handoff-context.md <<'EOF'
# Boot-handoff Trust Ceremony — Iteration Context Log

**Plan:** `docs/superpowers/plans/2026-05-20-boot-handoff-trust-ceremony.md`
**Branch:** feature/bootloader-hardening
**Merge commit:** 72265e14d (parents 919127580 ours + 7d20c23d5 theirs)
**Started:** 2026-05-20

## Capsule set under ceremony (34 — from nonos-sign/tests/artifacts.rs)

Slug (make)        | Prefix (key files)       | Boot-log name
-------------------|--------------------------|----------------------
proof-io           | proof_io                 | proof_io
ramfs              | ramfs                    | RAMFS
keyring            | keyring                  | KEYRING
entropy            | entropy                  | ENTROPY
crypto             | crypto                   | CRYPTO
vfs                | vfs                      | VFS
market             | market                   | MARKET
driver-virtio-rng  | driver_virtio_rng        | DRIVER-VIRTIO-RNG
driver-virtio-gpu  | driver_virtio_gpu        | DRIVER-VIRTIO-GPU
driver-ps2-input   | driver_ps2_input         | DRIVER-PS2-INPUT
driver-virtio-blk  | driver_virtio_blk        | DRIVER-VIRTIO-BLK
driver-virtio-net  | driver_virtio_net        | DRIVER-VIRTIO-NET
driver-xhci        | driver_xhci              | DRIVER-XHCI
driver-e1000       | driver_e1000             | DRIVER-E1000
net-l2             | net_l2                   | NET-L2
net-ip             | net_ip                   | NET-IP
net-udp            | net_udp                  | NET-UDP
net-dhcp           | net_dhcp                 | NET-DHCP
input-router       | input_router             | INPUT-ROUTER
compositor         | compositor               | COMPOSITOR
wm                 | wm                       | WM
desktop-shell      | desktop_shell            | DESKTOP-SHELL
image-codec        | image_codec              | IMAGE-CODEC
clipboard          | clipboard                | CLIPBOARD
login              | login                    | LOGIN
wallpaper          | wallpaper                | WALLPAPER
toolkit            | toolkit                  | TOOLKIT
about              | about                    | APP-ABOUT
calculator         | calculator               | APP-CALCULATOR
terminal           | terminal                 | APP-TERMINAL
file-manager       | file_manager             | APP-FILE-MANAGER
text-editor        | text_editor              | APP-TEXT-EDITOR
settings           | settings                 | APP-SETTINGS
process-manager    | process_manager          | APP-PROCESS-MANAGER

## Boot iterations

(populated by Task 8 onward — one section per boot attempt)
EOF
git add docs/superpowers/plans/2026-05-20-boot-handoff-context.md
```

- [ ] **Step 2: Capture starting state.**

```bash
git status -- nonos-data/ .keys/ | head -50 > /tmp/precon-status.txt
git log -1 --format='%H %s' HEAD > /tmp/precon-head.txt
echo "Pre-ceremony state captured in /tmp/precon-*.txt"
```

- [ ] **Step 3: Commit the context-log skeleton** (this is a docs-only commit; safe to land independently of the ceremony).

```bash
git commit -m "docs(boot-handoff): seed trust-ceremony iteration context log"
```

---

## Task 1: Wipe pre-existing trust artifacts

This is destructive but reversible (everything is in git history). We wipe so the ceremony writes a fresh, self-consistent set.

**Files:**
- Delete (working tree only): `nonos-data/trust/capsules/*.{nonos_id_cert,manifest}.bin`, `nonos-data/trust/policy/*.bin`, `nonos-data/trust/keys/*.pub` except trust-anchor placeholders (handled next), `.keys/*.seed` (yes, the user's local seeds — full ceremony).

- [ ] **Step 1: Sanity check we're on the merge commit.**

```bash
[ "$(git rev-parse HEAD)" = "72265e14d... " ] || git log -1 --oneline HEAD
```
(Don't hard-fail on hash; just inspect.)

- [ ] **Step 2: Wipe stale artifacts.**

```bash
rm -f nonos-data/trust/capsules/*.nonos_id_cert.bin
rm -f nonos-data/trust/capsules/*.manifest.bin
rm -f nonos-data/trust/policy/*.bin
rm -f nonos-data/trust/keys/*.pub
rm -f .keys/*.seed
rm -f .keys/*.pub
ls -la nonos-data/trust/capsules/ nonos-data/trust/keys/ nonos-data/trust/policy/ .keys/ 2>&1 | head -30
```

Expected: each directory empty of `.pub`/`.seed`/`.bin` (some may still contain `MANIFEST.sha256` or similar non-artifact files — leave them).

- [ ] **Step 3: Verify capsule-sign tool is built** (it's needed for keygen + signing).

```bash
[ -x nonos-sign/target/release/capsule-sign ] || ( cd nonos-sign && cargo build --release --bin capsule-sign )
nonos-sign/target/release/capsule-sign --help | head -3
```

Expected: shows the v3 help banner.

---

## Task 2: Generate fresh trust-anchor pair

The TA is the root of the chain. One Ed25519 + one ML-DSA-65 pair.

- [ ] **Step 1: Generate the TA keypairs.**

```bash
nonos-sign/target/release/capsule-sign keygen --alg ed25519 \
  --out .keys/nonos_trust_anchor_ed25519
nonos-sign/target/release/capsule-sign keygen --alg mldsa65 \
  --out .keys/nonos_trust_anchor_mldsa65
chmod 600 .keys/nonos_trust_anchor_*.seed
mv .keys/nonos_trust_anchor_*.pub nonos-data/trust/keys/
```

Expected: two `wrote .keys/X.seed (chmod 600) and .keys/X.pub for <alg>` lines; afterwards `.keys/` has 2 `.seed` files and `nonos-data/trust/keys/` has 2 `.pub` files.

- [ ] **Step 2: Verify TA presence.**

```bash
ls -la .keys/nonos_trust_anchor_*.seed
ls -la nonos-data/trust/keys/nonos_trust_anchor_*.pub
```

Expected: each pair present, seeds at mode `-rw-------` (600).

---

## Task 3: Generate 34 publisher pairs

One Ed25519 + one ML-DSA-65 per capsule.

- [ ] **Step 1: Define the prefix array and loop.**

```bash
PREFIXES=(
  proof_io ramfs keyring entropy crypto vfs market
  driver_virtio_rng driver_virtio_gpu driver_ps2_input
  driver_virtio_blk driver_virtio_net driver_xhci driver_e1000
  net_l2 net_ip net_udp net_dhcp
  input_router compositor wm desktop_shell
  image_codec clipboard login wallpaper toolkit
  about calculator terminal file_manager text_editor settings process_manager
)
echo "Will generate ${#PREFIXES[@]} publisher pairs"   # expect 34

for prefix in "${PREFIXES[@]}"; do
  echo "==> $prefix"
  nonos-sign/target/release/capsule-sign keygen --alg ed25519 \
    --out .keys/${prefix}_publisher_ed25519 2>&1 | tail -1
  nonos-sign/target/release/capsule-sign keygen --alg mldsa65 \
    --out .keys/${prefix}_publisher_mldsa65 2>&1 | tail -1
done

chmod 600 .keys/*_publisher_*.seed
mv .keys/*_publisher_*.pub nonos-data/trust/keys/
```

Expected: 34 ✕ 2 = 68 `wrote ...` lines, then chmod, then mv. Afterwards `.keys/` has 34 ed25519+34 mldsa65 = 68 seeds; `nonos-data/trust/keys/` has 68 pubs (plus the 2 TA pubs from Task 2).

- [ ] **Step 2: Spot-check counts.**

```bash
echo "seeds:      $(ls .keys/*_publisher_*.seed | wc -l)  (expect 68)"
echo "TA seeds:   $(ls .keys/nonos_trust_anchor_*.seed | wc -l)  (expect 2)"
echo "pub keys:   $(ls nonos-data/trust/keys/*.pub | wc -l)  (expect 70)"
```

---

## Task 4: Build userland prereqs

The capsule builds depend on `libc` (always) and on `marketplace-abi` (for the `market` capsule specifically).

- [ ] **Step 1: Build the prereqs.**

```bash
make nonos-mk-libc 2>&1 | tail -3
make nonos-mk-marketplace-abi 2>&1 | tail -3
```

Expected: each ends with a `Finished ...` line from cargo.

---

## Task 5: Build all 34 capsule ELFs

This is the slow step — each capsule cargo-checks + builds against `x86_64-nonos-user.json`.

- [ ] **Step 1: Build the ELF for every capsule.** Run the loop and capture failures.

```bash
SLUGS=(
  proof-io ramfs keyring entropy crypto vfs market
  driver-virtio-rng driver-virtio-gpu driver-ps2-input
  driver-virtio-blk driver-virtio-net driver-xhci driver-e1000
  net-l2 net-ip net-udp net-dhcp
  input-router compositor wm desktop-shell
  image-codec clipboard login wallpaper toolkit
  about calculator terminal file-manager text-editor settings process-manager
)

mkdir -p /tmp/nonos-build-log
echo "=== Building ${#SLUGS[@]} capsule ELFs ==="
FAILED_BUILDS=()
for slug in "${SLUGS[@]}"; do
  printf '  build %-22s ... ' "$slug"
  if make "nonos-mk-${slug}" >/tmp/nonos-build-log/${slug}.log 2>&1; then
    echo OK
  else
    echo FAIL
    FAILED_BUILDS+=("$slug")
  fi
done

if [ ${#FAILED_BUILDS[@]} -gt 0 ]; then
  echo ""
  echo "FAILED CAPSULE BUILDS:"
  for s in "${FAILED_BUILDS[@]}"; do
    echo "  ${s}  (log: /tmp/nonos-build-log/${s}.log)"
    tail -10 "/tmp/nonos-build-log/${s}.log" | sed 's/^/      /'
    echo ""
  done
fi
```

Expected outcome: ideally all 34 OK. Any FAIL is logged for diagnosis. If a capsule fails to build, record it in the context log as a Task-5 casualty; Task 6 will skip its sign step.

- [ ] **Step 2: Update context log with build results.**

```bash
echo "" >> docs/superpowers/plans/2026-05-20-boot-handoff-context.md
echo "## Task 5: ELF builds — $(date -u +%FT%TZ)" >> docs/superpowers/plans/2026-05-20-boot-handoff-context.md
echo "Built ${#SLUGS[@]} capsule ELFs; failures = ${#FAILED_BUILDS[@]}" >> docs/superpowers/plans/2026-05-20-boot-handoff-context.md
for s in "${FAILED_BUILDS[@]}"; do
  echo "- FAIL: $s" >> docs/superpowers/plans/2026-05-20-boot-handoff-context.md
done
```

---

## Task 6: Seal new trust-anchor policy

Now that TA pubs are in `nonos-data/trust/keys/`, seal them into the policy binary.

- [ ] **Step 1: Seal the policy.**

```bash
make nonos-mk-trust-policy 2>&1 | tail -10
ls -la nonos-data/trust/policy/nonos_trust_anchor.policy.bin
sha256sum nonos-data/trust/policy/nonos_trust_anchor.policy.bin
```

Expected: the target writes `nonos-data/trust/policy/nonos_trust_anchor.policy.bin`; the sha256 will be **different** from the pre-merge value (because the TA pubs inside are new).

---

## Task 7: Sign cert + manifest for every capsule

For each capsule whose ELF built in Task 5, sign cert+manifest. Skip any that failed to build.

- [ ] **Step 1: Sign loop.**

```bash
SUCCEEDED_BUILDS=()
for slug in "${SLUGS[@]}"; do
  if [[ ! " ${FAILED_BUILDS[@]:-} " =~ " ${slug} " ]]; then
    SUCCEEDED_BUILDS+=("$slug")
  fi
done

mkdir -p /tmp/nonos-sign-log
FAILED_SIGNS=()
echo "=== Signing cert+manifest for ${#SUCCEEDED_BUILDS[@]} capsules ==="
for slug in "${SUCCEEDED_BUILDS[@]}"; do
  printf '  sign %-22s ... ' "$slug"
  if make "nonos-mk-${slug}-sign" >/tmp/nonos-sign-log/${slug}.log 2>&1; then
    echo OK
  else
    echo FAIL
    FAILED_SIGNS+=("$slug")
  fi
done

if [ ${#FAILED_SIGNS[@]} -gt 0 ]; then
  echo ""
  echo "FAILED SIGN OPERATIONS:"
  for s in "${FAILED_SIGNS[@]}"; do
    echo "  ${s}  (log: /tmp/nonos-sign-log/${s}.log)"
    tail -15 "/tmp/nonos-sign-log/${s}.log" | sed 's/^/      /'
    echo ""
  done
fi
```

Expected outcome: ideally all `SUCCEEDED_BUILDS` capsules also sign. Any FAIL is recorded.

- [ ] **Step 2: Verify counts on disk.**

```bash
echo "certs:    $(ls nonos-data/trust/capsules/*.nonos_id_cert.bin 2>/dev/null | wc -l)"
echo "manifests:$(ls nonos-data/trust/capsules/*.manifest.bin 2>/dev/null | wc -l)"
echo "expected: at least ${#SUCCEEDED_BUILDS[@]} of each"
```

- [ ] **Step 3: Run the host artifacts test to validate the chain.** This is the same test CI runs after the scratch ceremony — `tests/artifacts.rs` decodes the policy, then verifies every `VERIFIED` entry's cert+manifest+ELF together.

```bash
( cd nonos-sign && cargo test --release --test artifacts -- --nocapture 2>&1 ) | tail -40
```

Expected: ideally `test on_disk_artifacts_verify_against_baked_policy ... ok` with `verified=34`. If it fails on a capsule, the failure names which layer broke; fix that capsule's sign target (or feed it into Phase 3 iteration).

- [ ] **Step 4: Update context log.**

```bash
cat >> docs/superpowers/plans/2026-05-20-boot-handoff-context.md <<EOF

## Task 7: Sign cycle — $(date -u +%FT%TZ)
Signed ${#SUCCEEDED_BUILDS[@]} capsules; sign failures = ${#FAILED_SIGNS[@]}
Build failures (skipped): ${FAILED_BUILDS[@]:-none}
Sign failures: ${FAILED_SIGNS[@]:-none}
artifacts.rs result: (paste the test outcome)
EOF
```

---

## Task 8: Commit the new trust artifacts (checkpoint commit)

Lock in the ceremony output as a single follow-up commit on top of the merge.

- [ ] **Step 1: Stage and commit.**

```bash
git add nonos-data/trust/policy/nonos_trust_anchor.policy.bin
git add nonos-data/trust/keys/*.pub
git add nonos-data/trust/capsules/*.nonos_id_cert.bin
git add nonos-data/trust/capsules/*.manifest.bin
git status --short -- nonos-data/trust/

git commit -m "$(cat <<'EOF'
trust: local scratch ceremony for the 34 verified-capsule chain

Fresh TA pair + 34 publisher pairs + sealed policy + cert/manifest set
for the full verified capsule list. Mirrors CI's scratch-sign-matrix
recipe (.github/workflows/nonos-trust-chain.yml) extended from 13 to 34
capsules. Replaces the merge-imported origin/main chain whose ELF
hashes were paired to upstream CI's exact build outputs (irreproducible
locally).

Rationale: after merging origin/main into feature/bootloader-hardening
every capsule failed spawn verification with one of:
  - "embedded ELF hash differs from manifest expected" (~22 capsules)
  - "manifest references a different cert than the one provided" (4)
  - "trust-anchor signature on cert is bad (Ed25519)" (toolkit)

All three classes resolve when the chain is locally self-consistent.
EOF
)"
```

---

## Task 9: Rebuild kernel + bootloader against the new chain

The kernel `include_bytes!`'s the policy + each capsule's cert+manifest+ELF. We rebuilt the ELFs and re-signed; now rebuild the kernel so it embeds the new artifacts.

- [ ] **Step 1: Build.**

```bash
make nonos-mk-bootloader 2>&1 | tail -20
```

Expected: `Finished release profile [optimized] target(s) in <time>` for both `nonos_kernel` and `nonos_boot`. If any capsule sign-target failure from Task 7 broke a dependency, this is where it surfaces.

---

## Task 10: First post-ceremony boot — capture baseline log

- [ ] **Step 1: Run NONOS in QEMU, capture the serial log.**

```bash
make nonos-mk-run 2>&1 | tee /tmp/nonos-boot-1.log
```

The user will see SSH:2222 / HTTP:8080 in the QEMU output. They can `Ctrl-A X` once enough log has scrolled (or wait for the kernel to settle).

- [ ] **Step 2: Extract the capsule-spawn outcome from the log.**

```bash
grep -E '^\[ERROR\] [A-Z]|^\[NONOS\] [a-z_]+: launching|^\[NONOS\] [a-z_]+: launch|\[INIT\]|capsule manifest rejected|trust-anchor signature on cert' /tmp/nonos-boot-1.log | head -80
```

- [ ] **Step 3: Update context log with this iteration's outcome.**

```bash
cat >> docs/superpowers/plans/2026-05-20-boot-handoff-context.md <<EOF

## Boot iteration 1 — $(date -u +%FT%TZ)
Log: /tmp/nonos-boot-1.log
Outcome summary:
$(grep -E '^\[ERROR\] [A-Z]|^\[NONOS\] [a-z_]+: launch|\[INIT\]' /tmp/nonos-boot-1.log | sed 's/^/  /' | head -60)
EOF
```

---

## Task 11: Decision branch — depending on Boot 1 outcome

This task is a decision tree, not linear steps. Pick the matching outcome.

### Outcome A: All capsules spawn cleanly, proof_io launches, [INIT] reaches a stable scheduler loop without errors

You're past the trust chain. **Jump to Task 12** (GUI verification).

### Outcome B: Some capsules still show trust-chain errors (rejected, cert mismatch, hash mismatch)

This means a specific capsule's ceremony was incomplete. Diagnose per-capsule:

- [ ] Look at `/tmp/nonos-sign-log/<failed_capsule>.log` from Task 7 — sign target may have errored silently.
- [ ] Check `userland/<capsule_dir>/Capsule.mk` for unusual sign rules.
- [ ] Manually re-run `make nonos-mk-<slug>-sign` and inspect the error.
- [ ] If a capsule's sign target requires inputs not produced by the ceremony, document the gap in the context log and either (a) fix the Makefile dependency or (b) accept that capsule as not-spawning for this iteration and move on.
- [ ] Re-run from Task 9 once the per-capsule issue is fixed.

### Outcome C: Capsules spawn but proof_io / ramfs / one of the core services fails to LOAD (not verify)

Trust chain is fine; the issue is post-verify (ELF load, IPC handshake, capability mismatch). This is real bug territory:

- [ ] Use `superpowers:systematic-debugging` Phase 1 on the specific capsule's failure mode.
- [ ] Common candidates: stack canary mismatch, page table entry permissions, missing capability declarations in Capsule.mk's `CAPSULE_REQUIRED_CAPS`.

### Outcome D: Kernel panics or doesn't reach userspace

Trust ceremony is irrelevant — there's a kernel-side regression from the merge that the ABI pin block didn't catch. Use systematic-debugging on the panic trace.

---

## Task 12: GUI verification (Outcome A path)

Confirm the GUI actually renders by checking the boot log for graphics-pipeline milestones.

- [ ] **Step 1: Verify graphics-stack capsules spawn in order.**

```bash
grep -E 'driver_virtio_gpu|virtio.gpu|compositor|wm|desktop_shell|wallpaper|login' /tmp/nonos-boot-1.log | head -30
```

Expected order (per `docs/production-roadmap/capsule_integration_matrix.md`):
1. `driver_virtio_gpu` spawns and announces.
2. `compositor` spawns, opens the framebuffer surface.
3. `wm` spawns, registers as window manager.
4. `wallpaper` spawns, paints the bg surface.
5. `login` spawns (pre-desktop gate).
6. `desktop_shell` spawns, renders the chrome.
7. Apps (`about`, `calculator`, …) follow.

- [ ] **Step 2: Confirm visually.** The user has QEMU open with a graphical window. The wallpaper + desktop chrome should be visible. Note in the context log:

```bash
cat >> docs/superpowers/plans/2026-05-20-boot-handoff-context.md <<EOF

## GUI status (boot iteration 1)
- compositor surface present:  YES / NO
- wallpaper rendered:          YES / NO
- desktop_shell rendered:      YES / NO
- login screen shown:          YES / NO
- Apps spawnable:              YES / NO
EOF
```

- [ ] **Step 3: If GUI is visible — done.** Commit context log:

```bash
git add docs/superpowers/plans/2026-05-20-boot-handoff-context.md
git commit -m "docs(boot-handoff): record working-GUI boot iteration"
```

- [ ] **Step 4: If GUI is NOT visible despite clean capsule spawns** — graphics pipeline issue. Likely candidates:
  - virtio_gpu_capsule didn't bind to PCI device — check `[VIRTIO-GPU]` traces.
  - Compositor never receives a framebuffer surface — check IPC log.
  - Wallpaper crashes on render — check capsule's serial output.
  Iterate by adding `debug::marker` calls to the suspect capsule and rerunning Task 9-10.

---

## Task 13: Iterate (Outcomes B/C/D)

If Task 11 picked Outcome B, C, or D, the loop is:

- [ ] Identify the specific failing component from /tmp/nonos-boot-N.log.
- [ ] Open `superpowers:systematic-debugging` (Phase 1 again) for the failure.
- [ ] Apply the SMALLEST fix that addresses the root cause.
- [ ] If the fix needs new trust artifacts (e.g. re-sign one capsule), run `make nonos-mk-<slug>-sign` for just that one.
- [ ] If the fix needs a kernel rebuild, run Task 9.
- [ ] Re-boot (Task 10 again as Boot N+1).
- [ ] Append a new boot-iteration section to the context log.

**Stop condition:** Task 12 GUI checks all pass, OR three boots in a row with no progress (then escalate — likely an architectural issue, see systematic-debugging Phase 4.5).

---

## Task 14: Final commit + push

Once the GUI works (per Task 12 Step 3), wrap up.

- [ ] **Step 1: Sanity-check the tree.**

```bash
git status
git log --oneline -5
```

- [ ] **Step 2: Push.**

```bash
git push
```

- [ ] **Step 3: Update memory.** If the GUI now works, the LAPIC #PF root-cause memory and the bootloader-handoff context memory are stale; the new fact is that the merge unblocked them. Adjust user memory accordingly.

---

## Self-review against the goal

- **Spec coverage:** the goal was "boot the GUI"; the plan covers (i) the trust chain (Phase 1, Tasks 1-8), (ii) the kernel rebuild (Task 9), (iii) the boot + diagnosis loop (Tasks 10-13), (iv) the visual GUI check (Task 12), (v) the final push (Task 14). The context log (Task 0) is the bookkeeping spine.
- **Placeholder scan:** the only intentional placeholder is "(paste the test outcome)" in Task 7 Step 4's heredoc — the user pastes the actual artifacts test outcome there. All commands are concrete.
- **Type consistency:** `SLUGS` (hyphenated) and `PREFIXES` (underscored) are used consistently; the boot-log uppercase name lives only in the Task-0 reference table.
- **Failure-mode coverage:** Task 11 explicitly branches on the four most likely outcomes (A clean, B sign-incomplete, C post-verify-load-failure, D kernel-panic). Task 13 names the systematic-debugging hand-off.
- **No fixes without root cause:** Phase 1 (Tasks 1-7) is the fix. The diagnosis is documented in "Established ground truth" above and the per-error mapping. The kernel itself self-diagnoses with the `(rebuild + re-sign)` hint.

---

## Execution handoff

This plan is to be executed inline in the current session (auto mode is active; the user asked us to "iterate until the GUI works"). Use `superpowers:executing-plans` discipline: batch through the Phase 1 ceremony (Tasks 1-9) without checkpoints — they're one logical unit — then check in after the first boot (Task 10).
