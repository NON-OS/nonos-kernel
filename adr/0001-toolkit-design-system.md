# ADR 0001: one design system, in the toolkit

**Status:** proposed, 2026-10-16. Branch `feat/toolkit-design-system`, stacked on #621.

## Context

The aim: an app's interface should take far less code to write, and every app should follow
the theme the person picks. What the tree holds today:

- 37 `theme.rs`, `palette.rs`, `tokens.rs` and `colors.rs` files under `userland/`. 19 capsules
  keep their own `theme.rs` and 18 their own `metrics.rs`; `0xFF35C4E2` is written out in 8 crates.
- The toolkit already carries three partial systems, and no app draws with any of them:
  - `theme/`: 8 schemes of 5 seed colours, with `derive`, `legible` and `contrast`, checked by
    `theme_proofs` (28 tests pass). It is read through a store fed over `TOOLKIT_OP_THEME_GET`,
    whose reply has room for 5 colours; the one outside reader is `app_skeleton`.
  - `design/`: a 4-role `Palette` with defaults that disagree with `theme/`, plus `SpacingScale`,
    `TextStyle` and `Radius`. Read only inside the toolkit.
  - `components/`: 21 files, 594 lines, no caller outside the toolkit. `toggle_track` returns a
    colour and draws nothing; the painters take a raw `&mut [u32]` and skip `paint`.
- The one toolkit module apps do share is `decorations/metrics.rs`: plain constants a `use` away,
  read by 5 crates. The dependency an app must take is what decided adoption.
- Picking a theme is plumbed but not connected. The policy store keeps `Field::Theme` (0x0106,
  the 8 `THEME_LABELS`); Settings has no row for it, nothing reads it, `theme_of` has no caller,
  and no client sends `TOOLKIT_OP_THEME_APPLY`.
- A screen costs a lot: Settings' `ui/` is 2,680 lines, about 800 of them cards, rows and
  switches; App Store's is 1,157 and draws square cards where Settings draws round ones. Settings
  already holds working `PaintBuffer` widgets for all of it.

## Decision

1. Drawing needs no IPC. Tokens are plain data an app reaches with a `use`. The runtime store
   carries the person's choice between processes; it is not how a colour is read.
2. A theme stays a scheme of 5 seeds. The full palette, about 24 to 30 roles (hover, pressed,
   selected, focus, separator, on-accent, muted, quiet, disabled), is derived from the seeds with
   `theme::derive` and `theme::legible`. Status colours (ok, warn, danger) are fixed per scheme.
   `theme_proofs` proves every role of every scheme meets its contrast floor.
3. The theme list stays `THEME_LABELS` with high contrast as a flag, as `theme_of` takes them.
   Aurora stays the default. A Light theme is added as one label and one scheme; the existing
   `every_theme_name_has_a_scheme` proof keeps the two in step.
4. Only the theme index crosses processes. Settings gains a row for `Field::Theme`. The toolkit
   capsule reads it and serves index and revision on a new op; existing ops are unchanged.
   `app_skeleton` picks from the table compiled into every app. One capability change, the
   toolkit's, in its `Capsule.mk` and `spawn.rs`, instead of one per app.
5. Widgets live in a new `nonos_toolkit::widgets` on `PaintBuffer`, moved down from
   `capsule_settings/src/settings/ui`. Each widget has one geometry function that its painter and
   its hit test both call. Widgets read the palette themselves; an app names no colour.
   Every widget lives in this shared list, even one only a single app uses so far; an app
   keeps no private widgets. Adding one is a file in `widgets/` and its line in `widgets/mod.rs`.
6. Spacing, radius and text size are logical units, scaled once inside the widget, never by the
   caller.
7. A colour that carries alpha is its own type, and only the blending painters accept it.
8. The installer and wallet keep their own brand palette (`nonos_brand`). The demo apps (hello,
   qrgen, mdview, prove, gui_demo, egui_proof) move to the house palette.

## Not decided here

- Themes the person defines, which would need colours on the wire.
- Retiring `components/` and `design/color.rs`. They are dead code, reported rather than removed.
- How the toolkit learns that `Field::Theme` changed: polling the revision, or a policy notice.

## Consequences

- Apps write screens without colour literals, and the look changes in one place.
- Most of the work is wiring and moving code that exists and is already proven.
- Each app moves in its own commit. The desktop shell goes last; it needs a boot to verify.
- `theme/schemes/mod.rs` holds a struct, a const and a function, which `mod.rs` may not, and its
  comment names a test, `schemes_match_the_labels`, that is really `every_theme_name_has_a_scheme`
  in `theme_proofs`. Both get fixed when phase 1 touches the file.
