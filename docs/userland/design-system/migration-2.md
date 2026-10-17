# Migration, round 2

Round 1 put every app's colours on the theme, and moved Settings, App Store and Process
Manager onto shared widgets. Round 2 moves every remaining app onto shared widgets, as
[App inventory](app-inventory.md) lists them, and adds hover, press, focus and scale.

## Order

| Step | Work | Why there |
|---|---|---|
| 1 | `Pointer`, then hover and press in Settings, App Store, Process Manager | they already use widgets, so only the input is new ([Interaction](interaction.md)) |
| 2 | the version 2 widgets, smallest first: Column, Checkbox, Radio, IconButton, Tooltip, Toast, Menu, Dialog, Table | each app step needs some of them ([Widgets, version 2](widgets-v2.md)) |
| 3 | Clock, About, Snake, Calculator, App Store, Settings, Image viewer, mdview | small; they prove the version 2 widgets |
| 4 | File manager, Process Manager's tables, Audio player, Video player | medium; two private widget kits go |
| 5 | desktop shell: dock, menus, prompts, toasts | its own loop and glass; needs a boot |
| 6 | Terminal, Text Editor, then Browser in six parts | largest; Browser last |
| 7 | Login and Input probe, and the shared helpers | the last screens outside the theme |
| 8 | scale on ([Display scale](scaling.md)) | needs every app's metrics logical first |
| 9 | the toolkit's dead parts retired | each its own decision |

Each app moves as round 1 did: one commit per app, its proofs crate passing, its private widget
files deleted, and its UI folder added to `scripts/check_ui_literals.py`'s `SCOPES` once it is
clean. Hover and press come with each app's move, not as a separate pass.

## Screens still outside the theme

- `capsule_login/src/render/mod.rs`: `LOCKED_BG` and `BAR_COLOR`.
- `capsule_input_probe/src/render/mod.rs` and `setup/mod.rs`: a debug probe's `FG` and `BG`.
- The desktop shell: toasts (`toasts.rs:35-37`) and their tints (`state/notify.rs:37-39`), the
  Delete button (`delete_prompt.rs:17`), and the shadow (`panel.rs:44`).
- Kept by the owner's decision, and not migrated: the boot splash, the installer, the wallet and
  the setup wizard. The Browser's letter tiles and reader themes are content.

## Known bugs and weak spots

- Audio player: the background glows never show; `fall * peak / 10_000 / 100` is always 0
  (`ui/shell/ground.rs`).
- App Store: each tab's highlight is drawn 4 pixels narrower than its click area.
- Process Manager: the protected-process note is a disabled button, so it has no contrast floor.
- Terminal: under System, the search-match highlight reads 2.58:1 in Solarized and 3.90:1 in
  Nord.
- Text Editor: no control shows the current theme's name.
- Solarized: no hover wash, and its selection wash thins to 0x04. Nord's and Dracula's `danger`
  ends a pale red.

## To retire, each its own change

- `toolkit/src/theme/chrome/`, `toolkit/src/components/` (16 of 21 files have no caller) and
  `toolkit/src/design/color.rs`.
- The toolkit service's `TOOLKIT_OP_THEME_GET` and `TOOLKIT_OP_THEME_APPLY`, which nothing calls.
  Removing them is a wire change.
- `app_skeleton`'s `component_render`, which had no caller before this branch.
- Apps still look the toolkit service up at start and wait for it. Ending that wait changes boot
  order, so it is the owner's call.
- 13 icon files under `capsule_desktop_shell/src/render/icons/` that are not in the module tree.
  Pre-existing; reported, not deleted.

## Done when

- No app outside the owner's kept list draws a widget by hand. `app-inventory.md`'s middle column
  is empty.
- Every app shows hover, press and focus where it has controls.
- Every app on the skeleton draws at the display's scale, and its window grows to fit.
- Every migrated UI folder is in `check_ui_literals.py`'s `SCOPES` with no baseline entries.
- Every version 2 widget passes its bounds, hit and readability proofs.
- A boot on a 1× and a large panel shows it, after two `make nonos-mk-run` runs and a check of
  the staged `kernel.bin`.
