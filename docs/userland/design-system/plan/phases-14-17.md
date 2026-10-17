# Phases 14 to 17: the large apps, scale, and the end

## Phase 14: Terminal, Text Editor, Browser

Each keeps its own named themes beside System, as the owner decided, and keeps its content
painters: the VT grid, the document canvas, the web page.

| Step | App | Change |
|---|---|---|
| 14.1 | Terminal | Tabs replaces `tab_pill` and `tab_chip`. IconButton replaces `toolbar` and `tool_icon`. Menu replaces the command palette. Row and Field replace the header, footer, rails and find bar. The search highlight gets its own floor, which fixes 2.58:1 in Solarized. |
| 14.2 | Text Editor | Menu replaces the menu bar, the ribbon drops and the sidebar menu. IconButton replaces ribbon cells. Tabs replaces the tab bar. Switch, Row and NavItem replace `widget/*`. Card and Row make up the settings screen. The theme picker shows the current theme's name. |
| 14.3 | Browser: toolbar | IconButton and Pill replace `toolbar/buttons`, `pill`, `route`. |
| 14.4 | Browser: tab bar and sidebar | Tabs, NavItem and SectionHeader. |
| 14.5 | Browser: settings page | Button, Field, Separator, Row. |
| 14.6 | Browser: pop-ups | `select_list` becomes Menu, `bubble` Tooltip, `short_notice` Toast. |
| 14.7 | Browser: pages, start and reader chrome | Row, SectionHeader, Card, Pill, Button. |
| 14.8 | Browser: helpers | Its `wrap.rs`, `fit_text.rs` and both `Rect`s give way to the toolkit's. `paint/tokens/` keeps only what the named Light and Dark need. |

Each Browser step is one commit with `capsule_browser_proofs`, `capsule_browser_html_proofs` and
`browser_http_proofs` passing.

## Phase 15: the last screens, the helpers and the gate

| Step | Change | Commit |
|---|---|---|
| 15.1 | Login screen: `LOCKED_BG` and `BAR_COLOR` become roles, and it follows the theme | `refactor(login): take its colours from the theme` |
| 15.2 | Input probe: the same | `refactor(input_probe): take its colours from the theme` |
| 15.3 | Each wrap or truncate left in an app gives way to `widgets::text`, and each private `Rect` to the toolkit's, where the types agree | one commit per app |
| 15.4 | `check_ui_literals.py`'s baseline is emptied of every closed site, and each migrated folder is in `SCOPES` | `chore(scripts): close the literal baseline` |

## Phase 16: display scale

These steps follow [Display scale](../scaling.md).

| Step | Change | Boot |
|---|---|---|
| 16.1 | The skeleton calls `set_scale`, still passing 4 | no |
| 16.2 | Each app's `metrics.rs` turns logical, read through `scale().px`, one app per commit, with its proofs at 4, 5, 6 and 8 quarters | no |
| 16.3 | `fit_display` grows the content area by the scale | yes |
| 16.4 | The skeleton passes the real quarters | yes, on a 1× panel and on a large one |

## Phase 17: retire, verify and boot

| Step | Change |
|---|---|
| 17.1 | Retire `theme/chrome/`, `components/` and `design/color.rs`, each in its own commit, once nothing reads them |
| 17.2 | The toolkit service's unused theme operations, and `component_render`: a wire change, proposed to the owner first |
| 17.3 | The start-up wait for the toolkit service: the owner decides |
| 17.4 | Verification: every proofs crate, every touched crate's `cargo check` against its baseline, `make nonos-mk-static` |
| 17.5 | On the owner's machine: `make nonos-mk-verify`, `nix flake check`, and the boot |

## Done when

[Migration, round 2](../migration-2.md) lists the conditions. One pull request follows, if the
owner asks for one.
