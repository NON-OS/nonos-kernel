# Widgets

## Where they live

```
userland/toolkit/src/widgets/
├── mod.rs       the widget list: `mod` and `pub use` lines, nothing else
├── state.rs     State, shared by every widget
├── ink.rs       Ink and Tone, the meanings an app picks
├── rect.rs      rectangle helpers: inset, split, centre, contains, share
├── surface.rs   Surface, what a widget draws on
├── scrolled/    Scrolled, a Surface for a scrolled pane
├── draw/        the painters widgets share
├── text/        measure, place, truncate, tail, wrap
└── <name>.rs    one file per widget, or a folder when it outgrows 75 lines
```

`mod.rs` also re-exports `Rect`, so an app takes everything from `nonos_toolkit::widgets`.

## The contract

| Item | Shape | Rule |
|---|---|---|
| `new` | `pub fn new(..) -> Self` | takes only what the widget cannot be drawn without |
| builders | `pub fn note(self, &'a str) -> Self` and the like | a new option is a new method, so no caller breaks |
| `state` | `pub fn state(self, State) -> Self` | hover, focus, press, selection, disabled |
| `size` | `pub fn size(&self) -> (u32, u32)` | the preferred logical size |
| `draw` | `pub fn draw(&self, fb: &mut impl Surface, at: Rect)` | paints inside `at` and nowhere else |
| `hit` | `pub fn hit(&self, at: Rect, x: i32, y: i32) -> ..` | `bool`, or the part that was hit |

Each widget has one private geometry function from `at` to its parts. `draw` and `hit` both call
it, and nothing else computes a position.

A `PaintBuffer` is a `Surface`, so `widget.draw(fb, at)` draws at the buffer's own coordinates. A
scrolled pane draws through `Scrolled::new(fb, scroll)` instead: `at` is then in content
coordinates, each primitive moves up by `scroll` and is cut to the pane, and a rounded shape
cut by the edge reads square there. `hit` takes the same coordinates, so the app passes the
pointer's y plus the scroll.

## State and input

```rust
#[derive(Clone, Copy, Default)]
pub struct State { pub hovered: bool, pub focused: bool, pub pressed: bool, pub selected: bool, pub disabled: bool }
```

The app owns state and decides it from input. Widgets never see an `InputEvent`, because that
type lives in `app_skeleton`, which depends on the toolkit. The app matches the event kind and
passes the pointer's `x` and `y` to `hit`. Hover needs `PointerAbs`, and a pressed state needs
`ButtonDown` and `ButtonUp`. Keyboard focus is the app's to move; a widget only draws it.

States are drawn in one order everywhere: `disabled` turns the widget to the `disabled` role and
ignores the rest. `selected` fills with `accent_wash`, `hovered` adds `hover_wash`, `pressed`
takes the fill to `mix(fill, bg, 32)`, and `focused` adds `focus_ring` on top.

## Text helpers

`widgets::text` gives every app what 5 to 7 of them rewrite today: `width`, `centre_top` (the top
that centres a line in a box), `left`, `centre`, `right`, `truncate` (to a width, with `…`, cut on
a char boundary), `tail` (the end that fits, for fields) and `wrap` (lines that fit a width).
All of them measure with `measure_ttf` at the size `readable_px` gives.

## Tests

Each widget has tests in `theme_proofs/src/widget_tests/`, which draw the real widgets on the
host through the `nonos_toolkit` dependency, in all 32 state combinations, at three scales:

- **Bounds:** draw into a `PaintBuffer` over a `Vec<u32>`; every changed pixel lies inside `at`.
- **Hit agrees with draw:** `hit` is true on drawn pixels of the hit part, and false outside `at`.
- **Readable:** for every scheme and state, the widget's ink reads on its fill at the floor in
  [Colours](colours.md).
- **No literals:** `scripts/check_ui_literals.py` fails on any new `0x` ARGB literal under
  `toolkit/src/widgets/` or in a migrated app's UI, against a baseline that only shrinks.

## Adding a widget

1. Write `widgets/<name>.rs` to the contract above, using roles and sizes only.
2. Add `mod <name>;` and `pub use <name>::<Name>;` to `widgets/mod.rs`.
3. Add its tests to `theme_proofs`.
4. Add a row for it to the [Widget list](widget-list.md).

Any app can then `use nonos_toolkit::widgets::<Name>;`. If step 2 is missed, the import does not
compile, so nothing fails silently.
