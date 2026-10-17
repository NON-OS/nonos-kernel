# Phases 9 and 10: interaction and the version 2 widgets

## Phase 9: hover, press and focus

| Step | Change | Files | Proof | Commit |
|---|---|---|---|---|
| 9.1 | `Pointer`, as [Interaction](../interaction.md) specifies | `toolkit/src/widgets/pointer/`, `widgets/mod.rs` | `theme_proofs/src/widget_tests/pointer.rs`: hover, a press begun and ended on one widget, a press dragged off, touch | `feat(toolkit): a Pointer apps feed, and the State it gives` |
| 9.2 | Settings: hover and press on rows, switches, sliders, sidebar and search; the focus ring on its cursor | `capsule_settings/src/settings/ui/`, its event path | `capsule_settings_proofs`: a move inside one row asks for no repaint, and a move to the next asks for one | `feat(settings): rows and controls answer the pointer` |
| 9.3 | App Store: the same for cards, tabs and buttons; fix the tab highlight 4 px narrower than its click area | `capsule_app_store/src/store/ui/` | its proofs, and a test that each tab's highlight equals its hit box | `feat(app_store): cards and tabs answer the pointer` |
| 9.4 | Process Manager: the same for the sidebar and its controls | `capsule_process_manager/src/pm/ui/` | `apps_proofs` or its own crate | `feat(process_manager): controls answer the pointer` |

## Phase 10: the version 2 widgets

Each widget is one folder under `toolkit/src/widgets/`, plus its two lines in `widgets/mod.rs`
and its row moved from "Later" to a table in [Widget list](../widget-list.md). Each gets
`theme_proofs/src/widget_tests/<name>.rs` and `<name>_read.rs`: bounds in every state at three
scales and four box sizes, hit agreeing with draw, and ink read back from pixels at its floor in
every scheme.

| Step | Widget | Needs first | Commit |
|---|---|---|---|
| 10.1 | `Column` | none | `feat(toolkit): a Column that hands out rectangles` |
| 10.2 | `Checkbox` and `Radio` | none | `feat(toolkit): Checkbox and Radio widgets` |
| 10.3 | `IconButton` | `Button`'s kinds and the `icons` API | `feat(toolkit): an IconButton widget` |
| 10.4 | `Tooltip`, with its placement | `rect` helpers | `feat(toolkit): a Tooltip widget` |
| 10.5 | `Toast` | `Tone` | `feat(toolkit): a Toast widget` |
| 10.6 | `Menu`, with `place` and separators | `Pointer` | `feat(toolkit): a Menu widget drawn in the app's window` |
| 10.7 | `Dialog` | `Button`, `scrim` | `feat(toolkit): a Dialog widget` |
| 10.8 | `Table`, with `Col` widths and `Cell` hits | `rect::share`, `Scrolled` | `feat(toolkit): a Table widget` |

Particular proofs:

- **Menu:** `place` keeps the menu inside `bounds` from every corner, and a separator is never
  hit.
- **Dialog:** each button's hit is its `Button`'s, and the scrim covers the whole `at`.
- **Table:** the column widths add up to `at.w`; a header hit names its column; a row hit names
  its row and column; a long cell is truncated, never drawn over its neighbour.
- **Tooltip:** placed inside `bounds` whichever side of the anchor it opens on.

## Done when

- `widgets/mod.rs` lists 24 widgets and `Pointer`.
- `theme_proofs` passes with every new test.
- `docs/userland/design-system/widget-list.md` shows them as built.
- Settings, App Store and Process Manager show hover, press and focus.
