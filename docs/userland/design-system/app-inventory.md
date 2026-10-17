# App inventory: what each app still draws itself

Measured on `feat/toolkit-design-system` at `25d8f1177`. Paths are under each app's `src/`.

**Content** is drawing only that app does, such as a board, a document, a chart, terminal text or
album art. It stays private. Everything else moves to a shared widget, from version 1 or from
[version 2](widgets-v2.md).

| App | Replace with shared widgets | Drop | Keeps as content |
|---|---|---|---|
| Browser | toolbar `buttons`, `pill`, `route` → IconButton, Pill; `tabbar` → Tabs; sidebar `row`, `group_row` → NavItem, SectionHeader; settings `controls`, `field`, `lines` → Button, Field, Separator; `select_list` → Menu; `bubble` → Tooltip; `short_notice` → Toast; pages `rows`, `header`, `group_head`, `tab_grid` → Row, SectionHeader, Card; start `badge`, `hero`, reader `controls`, `panel` → Pill, Card, Button | `ui/wrap.rs`, `state/fit_text.rs`, `short_name.rs`, both `Rect`s | page canvas and document, glyphs, reader article, letter tiles |
| Text Editor | `menubar/*`, `ribbon/drop`, `sb_menu` → Menu; `ribbon/cell`, `paint`, `icons` → IconButton; `tabbar` → Tabs; `statusbar`, `activity_bar`, `sidebar` → Row, NavItem; `settings/*` → Card, Row, Switch; `widget/toggle`, `docrow`, `navlist`, `disclosure`, `sb_entry` → Switch, Row, NavItem; `home/*` → Card, Button | own wrap in `sidebar.rs`; 4 metrics files | document canvas, page breaks, table rules |
| Terminal | `tab_pill`, `tab_chip` → Tabs; `toolbar`, `tool_icon` → IconButton; `palette`, `palette_row` → Menu; `header`, `footer`, `rail_*`, `vt/find_bar` → Row, Field, SectionHeader | `paint/fit_text.rs`, `market/wrap.rs`; 2 metrics files | the VT grid, blocks, cursor, input line, splash, sparkline |
| Desktop shell | dock `bottom_taskbar`, `off_tile` → IconButton; menus `desktop_menu`, `menubar_menu`, `panel` → Menu; four prompts → Dialog; `toasts` → Toast; launchpad `dots` → Tabs | `layout.rs` `Rect`; 4 metrics files | wallpaper glass, top-bar glyphs, generated app icons |
| Audio player | `ui/widget/` `button`, `card`, `chip`, `row`, `slider`, `switch`, `header`, `tile` → Button, Card, Pill, Row, Slider, Switch, SectionHeader | `ui/paint.rs`, `ui/text.rs`, `geometry.rs` `Rect`, `metrics.rs` | `art/*`, `hero`, `eq`, `wave` |
| Video player | `ui/widget/` `chip`, `field`, `progress`, `scrollbar`, `section`, `empty` → Pill, Field, Progress, Scrollbar, SectionHeader, Label; `frame/sidebar` → NavItem; `player/header` → IconButton | `ui/paint/rrect.rs`, `shape.rs`, `layout.rs` `Rect` | `poster`, the video frame |
| Process Manager | `table`, `table_head`, `table_row` → Table; `screens/auth_row`, `auth_cells`, `ovw_auth_row`, `sec_row`, `authority` → Row, Table; `help/panel`, `help/row`, `inspector`, `sidebar`, `status_bar` → Card, Row, NavItem | `metrics.rs` | `cpu_chart`, `spark`, `insp_spark` |
| File manager | `chip`, `info_tag_chip`, `chrome_pill` → Pill; `chrome_card`, `chrome_glow` → Card; `list_check` → Checkbox; `paint_rows`, `paint_row_tile`, `paint_header`, `paint_footer`, `paint_sidebar` → Row, SectionHeader, NavItem | none | `search_hl`, file icons |
| Snake | `ui/button`, `card`, `toggle`, `bar` → Button, Card, Switch; `paint/home_cards`, `setup_chips`, `rank_rows`, `over_summary`, `play_rail` → Card, Pill, Row | `metrics.rs` | the board, snake, pieces, glow |
| Calculator | `paint/button`, `swap_key` → Button; `chips` → Pill; `history_row`, `unit_col`, `rail` → Row | `metrics.rs` | `bits` |
| About | `ui/card`, `chip` → Card, Pill; `sidebar`, `status_bar` → NavItem, Row; `runtime_meter` → Progress | `chip_wrap.rs`, `ui/text.rs`, `chrome.rs` `Rect`, `metrics.rs` | `chain`, `licenses_cols`, verify glyphs |
| App Store | the hand-drawn part of `ui/card`, and `ui/status` → Card, Pill | `ui/wrap.rs` (its comment at line 17 is stale), `metrics.rs` | none |
| Clock | `paint_tabbar` → Tabs | none | `paint_timer` |
| Settings | the `sidebar` and `status_bar` grounds → Card or `sunken` | `metrics.rs` | `net_signal` |
| Image viewer | `overlay` controls → IconButton | `nav.rs` `Rect` | the image, the gallery |
| mdview | none | `layout/wrap.rs`, `layout/metrics.rs` | the document |

Done, with nothing left: hello, gui_demo, gui_proof, egui_proof, qrgen, prove, input_proof and
game_2048, whose board is content.

The tables hold what to replace. [Migration, round 2](migration-2.md) holds the order, the screens
still outside the theme, the known bugs, and when the work is done.
