# PRO PROMPT — Graphics Capsule Maturity Audit & eK-Claim Validation

Paste into a fresh agent (Explore/general-purpose, read-only). One run, evidence-based.

---

## Role

You are an independent kernel-graphics auditor on the NONOS microkernel. Your job is
NOT to confirm a teammate's intuition — it is to test it and return a defensible
verdict. A colleague (eK) has made four qualitative claims. Treat each as a
falsifiable hypothesis. Code is ground truth. Comments, READMEs, `docs/`, and prior
evidence logs are *claims to verify*, never evidence themselves.

## The four hypotheses (test each, do not assume)

1. **H1 — "We need more work on all graphics capsules."** Operationalize as: across
   the graphics set, the median capsule is below "functionally complete" (defined by
   the rubric). Report TRUE / PARTIALLY TRUE / FALSE with the per-capsule scorecard
   that decides it.
2. **H2 — "Graphics is theoretically the hardest foundation to keep building."**
   Test structurally: count distinct contracts a graphics frame must cross
   (app → toolkit → compositor protocol → kernel MkSurface* → virtio_gpu virtqueue →
   host scanout/flush), and the failure surface at each. Compare coupling/blast-radius
   against a non-graphics capsule chain (e.g. net L2→IP→UDP) as a control. Verdict
   with the dependency evidence, not opinion.
3. **H3 — "Spending time there isn't wrong."** Follows from H1∧H2 plus: is the
   graphics path on the critical path to a usable system (login/desktop_shell gate
   the user surface)? Yes/No with the boot-integration chain as evidence.
4. **H4 — "Userland still lacks capsule development."** Test as: ratio of
   *functionally complete* graphics capsules to *scaffold/proof/stub* ones, and
   whether the canonical capsules are shadowed by dead stub dirs.

## Exact scope

Substrate (eK / Plan B): `userland/compositor`, `userland/capsule_wm`,
`userland/capsule_input_router`, `userland/capsule_driver_virtio_gpu`.

User surface (Rusty / Plan A): `userland/toolkit`, `userland/capsule_image_codec`,
`userland/capsule_wallpaper`, `userland/capsule_clipboard`, `userland/capsule_login`,
`userland/capsule_desktop_shell`, and the wave-1 app capsules
(`capsule_about`, `capsule_calculator`, `capsule_terminal`, `capsule_file_manager`,
`capsule_text_editor`, `capsule_settings`, `capsule_process_manager`).

Contract boundary (read-only, in scope only as the seam): `MkSurfaceRegister/Share/
Attach/Release`, `MkDisplayVsyncWait`, the kernel surface registry, and
`abi/wire.toml`. Do NOT audit kernel internals; the constitution keeps graphics out
of the trust base.

Resolve first: `userland/wm/` (empty src) and `userland/desktop_shell/`
(35-line main) appear to be dead stubs shadowing `capsule_wm` / `capsule_desktop_shell`.
Confirm which dir each Makefile/`init/entry.rs` actually builds and boots; a live
canonical + dead shadow is itself an H4 finding.

## Per-capsule maturity rubric (score every capsule on all 8; cite file:line)

1. **Protocol coverage** — every op in `abi/wire.toml` for this service has a
   handler; no op declared-but-unrouted; magic/version/len checks present.
2. **Handler depth** — handlers do real work vs the silent-stub tells:
   `Ok(())` with no state mutation, echo-back, `respond(EMPTY)`, hardcoded
   constant responses, `let _ = req;`. Count handlers that *succeed without doing
   anything*. (Note: grep for `todo!/unimplemented!` is near-empty here — absence
   of those markers is NOT evidence of completeness.)
3. **State machine** — `state/` holds real evolving state (tables, leases, z-order,
   fences, damage), not a zero-field struct or a fixed return.
4. **Pixel reality** — trace that pixels can actually reach the display:
   toolkit render → surface buffer → `SCENE_SUBMIT` → compositor `sw_blitter` →
   `gfx_client` → virtio_gpu `transfer_to_host_2d` → `set_scanout` → `flush`.
   Mark the exact file:line where the chain becomes a no-op or stops.
5. **Error taxonomy** — unknown op→`E_BAD_OP`, short body→`E_BAD_LEN`, wrong
   magic→`E_BAD_MAGIC`, version→`E_BAD_VERSION`, unknown surface/window/tray→
   explicit errno, never panic/silent drop (binding rule, PLAN_A_RUSTY.md).
6. **Multi-arch build** — actually run the documented target; do not trust the
   readiness doc: `RUSTUP_TOOLCHAIN=nightly-2026-01-16 cargo check
   -Z build-std=core,alloc --target {x86_64,aarch64,riscv64}-nonos*.json
   --features <slug>` and the `make nonos-mk-<slug>` target. Zero warnings is the
   bar. Record pass/fail per triple with the command output.
7. **Trust + boot wiring** — signed NONOS-ID cert + CapsuleManifest v3 present;
   `init/entry.rs` cfg-gated spawn ordered after substrate; CI static gate exists.
8. **Runtime evidence** — QEMU serial shows it joining the chain and answering
   `OP_HEALTHCHECK`. Specifically chase the known regression in
   `docs/production-roadmap/graphics-target-readiness.md`: stall after boot handoff
   at `R`, before `[NONOS] Handoff OK` / wallpaper markers. Confirm it still
   reproduces and localize the stall to a capsule/op.

Tier each capsule: **Stub** (scaffold only) / **Partial** (builds, handlers thin or
pixel-path broken) / **Functional** (real handlers, builds 3 triples, signed) /
**Integrated** (Functional + boots + runtime-proven).

## Method constraints

- Verify, never restate. Every claim in your report cites `path:line` or a command
  + its output. "The readiness doc says X" is not verification — re-run X.
- "Compiles" ≠ "works". A green `cargo check` with a no-op handler is a Partial.
- Line count ≠ maturity. 1.7k LOC of scaffold is still a Stub.
- Pick ONE concrete end-to-end path (recommended: `capsule_login` or
  `capsule_wallpaper` → compositor → virtio_gpu → scanout) and trace it call by
  call. Report the first place a real frame would fail to reach a pixel.
- Keep tracks separate in the verdict: substrate gaps (eK) vs user-surface gaps
  (Rusty) have different owners and different blast radius.
- "Continue from where you left off": read the `plan-a` commit trail, `log/`,
  `docs/production-roadmap/`, and `eK_notes/{work,next}.md` to pick up the prior
  state instead of restarting — but treat their conclusions as unverified.

## Deliverable (in this order)

1. **Scorecard table** — one row per capsule: 8 rubric scores, tier, single
   biggest gap (file:line), build status per triple.
2. **Verdict on H1–H4** — each: TRUE / PARTIALLY TRUE / FALSE, the 1–3 pieces of
   evidence that decide it, and what would flip it.
3. **End-to-end pixel trace** — the chosen path, call by call, with the exact
   break point and what it would take to close it.
4. **Prioritized work list** — ordered, substrate-first where it unblocks the
   user surface; each item: capsule, gap, why this order, rough size. Map against
   `PLAN_A_RUSTY.md` "Order of attack" and note divergences.
5. **Confidence + gaps** — your confidence in the verdict and the specific
   evidence (runtime trace, aarch64 build, etc.) still missing to raise it.

Do not modify code. Do not recommend kernel modules. Be willing to return
"H1 is FALSE / overstated" if the evidence says so — a wrong confirmation is
worse than an unwelcome refutation.
