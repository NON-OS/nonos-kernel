# Current state

Measured on `feat/toolkit-design-system` at `7c7d0f925`, which is #621's head plus ADR 0001.
Paths are under `userland/`.

## How apps draw today

- 37 theme or palette files. 19 capsules keep their own `theme.rs`, and 18 their own `metrics.rs`.
- The same colours are typed again and again: `0xFF35C4E2` in 8 crates, `0xFF0B1319` in 7.
- UI code: Settings `ui/` is 2,680 lines in 48 files, App Store 1,157, Process Manager 4,387.
- Every app works out its rectangles by hand. Five apps define their own `Rect`, besides the
  toolkit's, in two integer types.
- Apps paint at a fixed 1x (`capsule_settings/src/settings/ui/metrics.rs:19`). Only the installer
  scales, through `nonos_brand::scale`.
- Hover is tracked only by the audio player, the shell's menus and the browser's link bubble. No
  app draws a pressed state. A selected row is drawn three different ways.

## Widgets apps build for themselves

| Widget | Apps | Widget | Apps |
|---|---|---|---|
| text or search field | 9 | sidebar nav item | 5 |
| list row | 9 | pill, chip or badge | 5 |
| card or panel | 7 to 8 | progress bar | 4 |
| button | 7 | switch | 3 |
| tabs or segmented control | 6 | menu, icon button | 3 each |
| separator | 5 | scrollbar, slider, table | 2 each |
| section header | 5 | dialog, tooltip, chevron | 1 to 2 each |

Text helpers are rewritten as well: vertical centring in 5 apps, truncation in 7 (two with an
ellipsis), word wrap in 5. The toolkit has none of them.

## What the toolkit already has

| Module | Holds | Read by apps |
|---|---|---|
| `theme/schemes/` | 8 schemes of 5 seeds, all dark, and `HIGH_CONTRAST` | no; `theme_of` has no caller |
| `theme/chrome/` | 24 functions working colours out from the seeds | no |
| `theme/derive.rs`, `legible.rs`, `contrast.rs` | `mix`, `with_alpha`, `muted`, `quiet`, contrast floors | toolkit only |
| `theme/store/` | the theme in force in this process, with a revision | `app_skeleton` only |
| `theme/palette.rs` | fixed status colours: ok, warn, error, disabled | no |
| `design/` | spacing, text styles, radii, a 4-role palette | no |
| `components/` | 21 files of style structs; 16 have no caller | no |
| `decorations/metrics.rs` | window-frame sizes, as plain constants | yes, 5 crates |

`theme_proofs` already checks every scheme against the WCAG floors; its 28 tests pass.

## How a theme choice travels today

The policy store keeps `Field::Theme` (0x0106, a u8 over the 8 `THEME_LABELS`) and
`Field::HighContrast` (0x0111, a bool). Settings shows neither, and nothing reads them. Apart
from that, every full paint in `app_skeleton` asks the toolkit service for its revision and, when
it moves, for 5 colours. Nothing ever changes the service's theme, and the apps paint with their
own constants anyway.

## Defects found

| Where | Defect |
|---|---|
| `app_skeleton/src/clients/toolkit/theme.rs:46` | `mk_ipc_call` with no timeout: a silent toolkit stalls the app for the kernel's 5 s default |
| `app_skeleton/src/runner/paint_frame.rs` | the damage path skips the theme check, so a new theme waits for a full paint |
| `toolkit/src/theme/schemes/mod.rs` | holds a struct, a const and a function; its comment names `schemes_match_the_labels`, which is `every_theme_name_has_a_scheme` in `theme_proofs` |
| `toolkit/src/theme/legible.rs:22-23` | the doc comment on `MUTED_TARGET` stops mid-sentence |
| Settings `SUBLABEL_FG` | 4.26:1 on `CARD_BG`, under the 4.5:1 floor for body text |
| desktop shell `TEXT_MUTED` | 2.58:1 on the panel, under the 3:1 floor for large text |
| desktop shell top bar and `LINE` | translucent colours written with `fill_rect`, which does not blend |
| `capsule_desktop_shell/src/render/consent.rs:22` | a private opaque `PANEL` shadows `palette::PANEL` |
| Process Manager `WARNING` | a grey, used as muted text |
| the toolkit service's wire | not described in `docs/userland/ipc-services.md` or `abi/` |
