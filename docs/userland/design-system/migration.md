# Migration

The design system is built first, in the toolkit: roles, sizes, then the version 1 widgets. Apps
then move over one per commit, in this order.

| Step | Apps | Why there |
|---|---|---|
| 1 | Settings | most version 1 widgets come from it; its 2,680 `ui/` lines are the measure |
| 2 | App Store | square cards become the shared round ones; drops its own text, wrap and scrollbar |
| 3 | Process Manager | its sidebar is nearly Settings' own; tables wait for `Table` |
| 4 | About, Snake, hello, qrgen, mdview, prove, gui_demo, egui_proof | roles only, little to move |
| 5 | the other `app_skeleton` apps, one per commit | file manager, calculator, clock and the rest |
| 6 | Browser, Text Editor, Terminal, Audio player | own palettes; the first three gain "System" |
| 7 | desktop shell | its own loop, translucent glass and raw fills; needs a boot |

Steps 1 to 7 are done, one commit per app, and need a boot to confirm on screen. Toasts, the
shell's Delete button and its shadow keep their literals for a follow-up.

The installer, the wallet and `boot_splash` keep their own brand look and are not migrated. The
setup wizard keeps its own constants: it runs before any choice exists.

## Moving one app

1. Map each colour constant to a role. A constant that only shapes one widget goes away with that
   widget. The commit carries the mapping table.
2. Replace each hand-drawn widget with the shared one, and delete the private file.
3. Delete the `theme.rs` and `metrics.rs` entries left unused.
4. Run `cargo check` for the user target. The app's proofs crate must still pass.
5. Record the UI line count before and after.

## Settings, mapped

| Settings | Role |
|---|---|
| `WINDOW_BG` | `bg` |
| `SIDEBAR_BG` | `sunken` |
| `CARD_BG` | `surface` |
| `PILL_BG`, `SEARCH_BG` | `raised` |
| `CARD_BORDER`, `ROW_LINE`, `SIDEBAR_LINE` | `border` |
| `PILL_BORDER`, `SEARCH_BORDER` | `border_strong` |
| `TITLE_FG`, `CARD_TITLE_FG`, `LABEL_FG`, `SEARCH_FG` | `text` |
| `VALUE_FG` | `text_2` |
| `NAV_FG`, `SUBTITLE_FG`, `CARD_NOTE_FG`, `IDLE` | `muted` |
| `SUBLABEL_FG`, `SEARCH_PLACEHOLDER` | `quiet`, which also fixes its 4.26:1 |
| `ACCENT`, `OK`, `WARN` | `accent`, `ok`, `warn` |
| `NAV_FG_ACTIVE`, `NAV_BG_ACTIVE`, `NAV_BORDER_ACTIVE` | `accent_text`, `accent_wash`, `accent_edge` |
| `FOCUS_RING`, `ROW_HOVER_BG` | `focus_ring`, `hover_wash` |
| `SWITCH_*`, `TRACK_BG` | inside `Switch` and `Slider` |

## Per-app choices

- The Browser (#621), the Text Editor and the Terminal keep their own theme picker, and each
  gains "System" as its first option. "System" follows the OS theme and is the default.
- Colours shift slightly where an app's value and the shared formula differ. For example, App
  Store's cards become round. A migration accepts that shift; it does not add a role to match
  one app.

## Keeping it clean

- `scripts/check_ui_literals.py`, beside `check_allows.py`, fails on a new ARGB literal under
  `toolkit/src/widgets/` and in each migrated app's UI folder, against
  `scripts/baselines/ui-literals.txt`. An app joins its `SCOPES` as it moves.
- `theme_proofs` and the check are proposed for CI in a separate change, since that binds everyone.

## Done when

- Every version 1 widget is in `widgets/`, with its tests passing in `theme_proofs`.
- Every migrated app draws only with widgets and roles, and the literal check passes over them.
- On a boot, changing the theme in Settings restyles every migrated app and the shell within
  about a second. The boot needs two `make nonos-mk-run` runs, and the staged `kernel.bin` is
  checked for a changed capsule before the screen is trusted.
- Every role meets its floor in all 9 schemes and in high contrast.
- Each defect in [Current state](current-state.md) is fixed, or is filed as an issue.
- `docs/userland/writing-an-app.md` builds its example screen from widgets.
