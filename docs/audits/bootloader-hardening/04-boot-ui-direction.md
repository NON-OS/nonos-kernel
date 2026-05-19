# Boot-UI Direction — W6 (approved: ambition "Evolve", failure model B, determinism = back-buffer)

Direction document (what + why + 1-line fix directions). NOT an implementation/patch. No code modified by this doc. Constants cited by `name:value` from `nonos-bootloader/src/display/constants/`. Hardening findings derived from real source are in `01-findings-register.md` (`W6-NN`); cross-refs by ID only.

## §1 Visual language (inherited VERBATIM — no new palette)

Reuse `display/constants/colors.rs` and `display/constants/layout.rs` as-is:

- Accent / brand: `COLOR_ACCENT=0xFF00D4AA` (== `COLOR_PRIMARY=0xFF00D4AA`, `COLOR_LOGO_PRIMARY=0xFF00D4AA`), dim accent `COLOR_ACCENT_DIM=0xFF005544`.
- Surface: near-black `COLOR_BACKGROUND=0xFF000000`, glass panels `COLOR_GLASS_BG=0xFF080C10` / `COLOR_GLASS_BORDER=0xFF1A2228`, box `COLOR_BOX_BG=0xFF0A0F12`, border `COLOR_BORDER=0xFF1A2228`, panel corner radius `PANEL_RADIUS=8`.
- Stage-state colors: `COLOR_SUCCESS=0xFF00CC66`, `COLOR_ERROR=0xFFFF4444`, `COLOR_WARNING=0xFFFFAA00`, error surface `COLOR_ERROR_BG=0xFF1A0808`.
- Text hierarchy: `COLOR_TEXT_PRIMARY=0xFFE8F0F8` > `COLOR_TEXT_DIM=0xFF667788` > `COLOR_TEXT_MUTED=0xFF3A4450` (`COLOR_TEXT_WHITE=0xFFFFFFFF` reserved for the failed-row reason only).

No constant added or recolored. `display/boot/error.rs:25,29,30` currently uses raw literals `0xFF100000`/`0xFFFFFFFF`/`0xFF888888` instead of the palette — fix direction: replace with `COLOR_ERROR_BG`/`COLOR_TEXT_WHITE`/`COLOR_TEXT_MUTED` so the failure screen is in-palette.

## §2 Stage state model (FSM over the existing 11 stages)

`display/constants/stages.rs` defines `STAGE_INIT=0 … STAGE_COMPLETE=10` (11 stages). `display/boot/stage.rs:21-26` already has `StageStatus { Pending, Running, Success, Failed }` — promote it to the explicit FSM. Each stage ∈ exactly one of:

| State | Color | Meaning | Allowed transitions |
|-------|-------|---------|---------------------|
| pending | `COLOR_TEXT_MUTED` | not yet attempted | → active |
| active  | `COLOR_ACCENT`     | running, prior stage committed `passed` | → passed \| → failed |
| passed  | `COLOR_SUCCESS`    | committed success | terminal (per boot) |
| failed  | `COLOR_ERROR`      | committed failure | terminal (freezes UI) |

Transition rule: stage *N* may enter `active` only after stage *N-1* committed `passed`. Screen = pure function `render(stage_states[0..=10], frozen_log_tail)`; no other input. No partial frame: a stage shows `active` only via a committed frame, never mid-compute. Fix direction: drive the FSM from the existing `update_stage(stage,status)` call sites (`display/boot/stage.rs:33`) instead of free-form `log_*`.

## §3 Determinism mechanism (off-screen back-buffer + one atomic blit)

Today every draw writes the live framebuffer directly: `display/gop/draw.rs:26,34` `fb.offset(...).write_volatile(...)` straight to `FB_PTR` (`display/gop/state.rs:20`). Every stage tears mid-frame.

Direction: allocate one off-screen back-buffer sized `FB_STRIDE * FB_HEIGHT * 4` (≈ 8 MiB @ 1080p), allocated PRE-`ExitBootServices` (consistent with W4-08: zero post-EBS allocation — the back-buffer is reserved in the same Boot-Services-live window as the other handoff resources, never after the EBS at `handoff/exit/orchestrate.rs:87`). All `put_pixel`/`fill_rect`/`draw_string` retarget the back-buffer; the live `FB_PTR` is written by exactly ONE memcpy (atomic blit) per state commit, so the panel only ever displays a fully-composed frame.

Damage-tracked / partial-region redraw is explicitly REJECTED: it reintroduces the exact tearing class being removed and is fragile under the layout-underflow math (see W6-02). One full blit per commit is the determinism guarantee.

Decorative spin animations REMOVED (stage feedback = discrete committed frames, not animation): cross-ref W4-07 (`boot/crypto/hash.rs:42` `32×micro_delay` ≈ 48M iters hash-reveal), W4-03/W4-04 (`settle_delay`/`mini_delay`), W4-09 (verify `mini_delay` cluster). `display/boot/init.rs:36-38` `reset_animation`/`tick_animation` become no-ops by construction.

Layout grid uses the real `display/constants/layout.rs` values verbatim: `PANEL_PADDING=24`, `SECTION_GAP=16`, `PROGRESS_BAR_WIDTH=400`, `PROGRESS_BAR_HEIGHT=4`, `STATUS_BOX_WIDTH=400`, `STATUS_BOX_HEIGHT=24`, `HASH_BOX_WIDTH=520`, `HASH_BOX_HEIGHT=48`, `SIG_BOX_HEIGHT=80`, `ZK_BOX_HEIGHT=64`, `LOGO_SIZE=64`, `PANEL_RADIUS=8`. `HASH_ANIMATION_FRAMES=16`/`PROGRESS_ANIMATION_STEP=2` become unused once animation is removed. Stage rows laid out top-down: 11 rows × (`STATUS_BOX_HEIGHT=24` + `SECTION_GAP=16`) inside a glass panel inset by `PANEL_PADDING=24`; log tail below, clipped to the panel (closes the no-panel-clip class in W6-02/W6-03).

## §4 Failure UX (Model B — concrete, terminal, one committed frame)

On the first stage that commits `failed`, freeze the FSM and render ONE final composed frame, then blit once:

- Every stage that committed `passed`: row in `COLOR_SUCCESS`.
- The failed stage: row text `COLOR_ERROR` on a `COLOR_ERROR_BG=0xFF1A0808` band, plus ONE bounded reason line in `COLOR_TEXT_WHITE`. Bounded-reason rule: the reason is a fixed `&'static [u8]` per failure class (or a stack `[u8; N]`), `len` capped exactly as the log path already caps (`display/log_panel/entry.rs:36` `msg.len().min(LOG_LINE_LEN)`, `LOG_LINE_LEN=120`) and additionally clipped horizontally to the panel — never an unbounded/attacker-derived string (see W6-03).
- Every stage after the failed one: `COLOR_TEXT_MUTED`, suffixed `(not reached)`.
- The frozen log tail (last N `LogEntry`, `display/log_panel/buffer/storage.rs`) below, in its level colors.
- A halt banner in `COLOR_ERROR`.

Terminal state: no input is read after the failure frame (the `menu/run.rs:31` poll loop is not re-entered; the only post-failure path is power-cycle). One committed frame; no continue affordance, no spinner. The failure renderer must not allocate — `display/boot/error.rs:21-31 show_error_screen` already allocation-free; keep it so (W6-05, clean; cross-ref W5-05 for the orthogonal zeroization gap — the failure path renders but does not zeroize).

## §5 Fail-closed menu semantics (closes W3-01; W6-04 is the resolution-path proof)

Today (`entry/action.rs:25`): `MenuAction::Timeout | MenuAction::Continue => Ok(SecurityMode::Standard)`. Timeout (`menu/run.rs:66`) and Cancel/ESC/`q` (`menu/run.rs:52`) both resolve to `Standard` (signature required, but NOT secure-boot+TPM — `menu/types/mode.rs:29-30`). Unrecognized input maps to `KeyAction::None` (scancode default `menu/input/keys.rs:33`, char default `menu/input/keys.rs:44`) → `menu/run.rs:54` no-op → eventually timeout → `Standard`. `SecurityMode::Development` is an ungated menu entry (W3-01, `menu/types/state.rs:22`, owns the S1).

Invariant (shared by §4 and §5): **ambiguity → MORE-verified, never less.**

Direction:

1. Menu timeout AND any invalid/unrecognized input resolve to the HIGHEST-verified path (full sig + ZK, i.e. `SecurityMode::Hardened`), never `Standard`, never `Development`. 1-line fix direction: change the `Timeout | Continue` arm at `entry/action.rs:25` to `Ok(SecurityMode::Hardened)` and make `KeyAction::None`/`Cancel` resolve up, not to `Continue`.
2. `SecurityMode::Development` is unreachable unless a compile-time floor explicitly permits it. Gate the `Development` `DEFAULT_ENTRIES` slot (`menu/types/state.rs:22`) AND the `resolve_action` `Development` mapping behind the SAME cfg as the trust posture — pattern already proven correct for the F12 path: `entry/dev.rs:35-38` `#[cfg(not(feature="dev-mode"))] dev_override → false` (W3-12). Reuse that exact gate so a console actor on a `production`/`hardened` binary cannot select an unsigned mode (this is the W3-01 closure direction).
3. The failure screen (§4) and the menu share the invariant: there is no input, timeout, or parse outcome that yields a less-verified boot than the explicit user choice would.
