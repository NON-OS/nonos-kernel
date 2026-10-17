# Phases 11 to 13: the apps, and the desktop shell

Every step follows [App inventory](../app-inventory.md) for what to replace and what stays as
content, and the rules in [the plan](README.md). Each step also:

- wires hover, press and focus for the controls it moves;
- deletes the private files it replaces;
- adds the app's UI folder to `SCOPES` in `scripts/check_ui_literals.py`.

Commits read `refactor(<app>): draw with the shared widgets`, unless the step says otherwise.

## Phase 11: small apps

| Step | App | Uses | Also |
|---|---|---|---|
| 11.1 | Clock | Tabs | none |
| 11.2 | About | Card, Pill, NavItem, Row, Progress | drop `chip_wrap.rs`, `ui/text.rs`, the `Rect` in `chrome.rs`, and `metrics.rs` entries it orphans |
| 11.3 | Snake | Button, Card, Switch, Pill, Row | drop `ui/button.rs`, `card.rs`, `toggle.rs`, `bar.rs` |
| 11.4 | Calculator | Button, Pill, Row | the keypad keeps its grid; each key is a `Button` |
| 11.5 | App Store | Card, Pill | finish `ui/card.rs` and `ui/status.rs`; drop `ui/wrap.rs` for `widgets::text::wrap` |
| 11.6 | Settings | Card or `sunken` grounds | the sidebar and status bar grounds; then `metrics.rs` holds only what is Settings' own |
| 11.7 | Image viewer | IconButton | the overlay; drop the `Rect` in `nav.rs` |
| 11.8 | mdview | `widgets::text::wrap` | drop `layout/wrap.rs` if the shared wrap covers its runs; keep it and say why if not |

## Phase 12: medium apps

| Step | App | Uses | Also |
|---|---|---|---|
| 12.1 | File manager | Pill, Card, Checkbox, Row, SectionHeader, NavItem | none |
| 12.2 | Process Manager | Table, Row, Card | the protected-process note becomes a `Label` in `muted`, not a disabled button |
| 12.3 | Audio player | Button, Card, Pill, Row, Slider, Switch, SectionHeader | delete `ui/widget/` but `hero`, `eq` and `wave`, which are content; drop `ui/paint.rs`, `ui/text.rs` and the `geometry.rs` `Rect`; fix the glows in `ui/shell/ground.rs` as `fix(audio_player): ...`, in its own commit |
| 12.4 | Video player | Pill, Field, Progress, Scrollbar, SectionHeader, Label, NavItem, IconButton | delete `ui/widget/` but `poster`; drop `ui/paint/rrect.rs`, `shape.rs` and the `layout.rs` `Rect` |

## Phase 13: the desktop shell

The shell runs its own loop and paints through its own `fill` helpers on two layers. Each step
lands alone, and phase 13 is believed only after a boot.

| Step | Change | Commit |
|---|---|---|
| 13.1 | The shell's drawing helpers implement `Surface`, so widgets draw on its layers | `feat(shell): widgets draw on the shell's layers` |
| 13.2 | The menus in `desktop_menu` and `menubar_menu` become `Menu`, with hover through `Pointer` | `refactor(shell): menus are the shared Menu` |
| 13.3 | The four prompts become `Dialog`. The Delete button is a `Danger` `Button`, so its fixed red goes. | `refactor(shell): prompts are the shared Dialog` |
| 13.4 | Toasts become `Toast`; the tints in `state/notify.rs` become tones | `refactor(shell): toasts are the shared Toast` |
| 13.5 | The dock's tiles become `IconButton`s; launchpad `dots` becomes `Tabs` | `refactor(shell): the dock draws with shared widgets` |
| 13.6 | The menu and dock shadow takes the `shadow` role | `refactor(shell): the shadow is the theme's` |

The proof for each step is `desktop_proofs`, plus a check that the shell's palette tests still
hold. On the boot, look at the menus, the prompts, the toasts and the dock in a dark theme and
in Light.
