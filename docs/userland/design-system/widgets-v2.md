# Widgets, version 2

Version 1 holds the 15 widgets in [Widget list](widget-list.md). Apps still draw these others
by hand, so version 2 adds them, to the same contract: `new`, builders, `.state(State)`, `size`,
`draw` into a `Rect`, `hit`, and one geometry function shared by `draw` and `hit`
([Widgets](widgets.md)). Each gets tests in `theme_proofs/src/widget_tests/` for bounds, hit and
readability in every scheme and state, the same as version 1.

| Widget | `new` | Builders | `hit` returns | Draws | Replaces, in |
|---|---|---|---|---|---|
| `Column` | `(at)` | `.gap(u32)` | none | hands out `Rect`s down a box: `next(h)`, `rest()` | hand-stacked layouts everywhere |
| `Checkbox` | `(on)` | `.label(&str)` | `bool` | a box with a tick | File manager `list_check.rs` |
| `Radio` | `(selected)` | `.label(&str)` | `bool` | a ring with a dot | option groups drawn as chips |
| `IconButton` | `(IconId)` | `.kind(Kind)`, `.label(&str)` | `bool` | an icon, with an optional label | toolbars in Browser, Terminal, Text Editor |
| `Tooltip` | `(text)` | `.below()` | none | a small label box by an anchor | Browser `bubble.rs` |
| `Toast` | `(text)` | `.tone(Tone)`, `.action(&str)` | `bool`, the action | a notice panel | shell `toasts.rs`, Browser `short_notice.rs` |
| `Menu` | `(&[Item])` | `.hovered(Option<usize>)` | `Option<usize>` | a panel of rows, with separators and shortcuts | shell menus, Text Editor menus, Terminal palette, Browser `select_list.rs` |
| `Dialog` | `(title)` | `.body(&str)`, `.buttons(&[(&str, Kind)])`, `.focus(usize)` | `Option<usize>`, the button | a panel over a scrim | the shell's four prompts |
| `Table` | `(&[Col])` | `.rows(&[&[&str]])`, `.sort(col, up)`, `.selected(Option<usize>)` | `Option<Cell>`, a row or a header | a header and rows of cells | Process Manager `table*.rs`, Video player `table.rs` |

## Rules particular to these

- **Menu and Tooltip draw inside the app's own window,** over what is already painted. A
  separate popup window (`WindowKind::Popup`) is left for later.
  - `Menu::place(anchor, bounds)` returns the `Rect` to draw at. It opens below the anchor, and
    flips above or shifts left to stay inside `bounds`.
  - The app closes the menu when a press lands outside that `Rect`.
- **Tooltip:** the app decides when to show it, after a pause it times itself with `on_tick`;
  the widget only draws it, placed inside `bounds` on whichever side of the anchor fits.
- **Dialog:** the app keeps the focused button. Its buttons are `Button`s, so they press and
  focus like any other. The scrim is the `scrim` role, drawn with a blend.
- **Table:** it draws only the rows it is given, so a long list passes the visible slice with
  `.first(k)`, the slice's index in the whole list, and scrolls by whole rows under a header
  that stays put. Drawn through `Scrolled`, the whole table scrolls, header too. A `Col` is a title and a width, fixed or a share of what is left
  (`rect::share`). `Cell` says which row and column were hit, or which header, for sorting.
- **Toast:** it draws the tones that `Pill` already has: `Plain`, `Accent`, `Ok`, `Warn`,
  `Danger`. The shell's Info, Warn and Error map to `Accent`, `Warn` and `Danger`.
- **Column:** it is not a layout engine. It hands out rectangles in order, so a screen stops
  adding up `y` by hand.

## Still later

- A popup window for menus that must leave the app's window, such as the shell's menu bar.
- Text selection inside `Field`; editing stays the app's.
- Drag and drop, and animation.
