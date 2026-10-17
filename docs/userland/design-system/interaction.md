# Interaction: hover, press and focus

Every widget draws five states through `State`: hovered, focused, pressed, selected and disabled.
No app reports hover or press today, except the desktop shell's menus. So nothing on screen
answers the pointer until it is clicked.

## What already arrives

The skeleton subscribes every app to absolute pointer moves, button down and up, wheel and touch,
whatever its manifest asks for (`app_skeleton/src/setup/input_mask.rs:27-40`). Positions arrive
in content coordinates. No new wiring is needed to see the pointer.

## The design

The toolkit gains `widgets::Pointer`: plain data the app keeps, one per window. The toolkit
cannot see `InputEvent`, which lives in `app_skeleton`, so the app passes in the fields.

```rust
pub struct Pointer { /* where it is, where a held press began, and whether a finger */ }

impl Pointer {
    pub fn moved(&mut self, x: i32, y: i32);
    pub fn pressed(&mut self, x: i32, y: i32);
    pub fn touched(&mut self, x: i32, y: i32);
    pub fn released(&mut self);
    pub fn left(&mut self);
    pub fn position(&self) -> Option<(i32, i32)>;
    pub fn state(&self, hit: impl Fn(i32, i32) -> bool) -> State;
}
```

- **Hovered:** the pointer is where the widget's `hit` answers.
- **Pressed:** hovered, with the button down, and the press began on the same widget. A press
  dragged off a button and released there does not click it.
- **Hovered target:** the app names what is under the pointer with its own small enum, and asks
  for a repaint only when that changes. Moving across one row repaints nothing; crossing to the
  next row repaints once.
- **Touch:** a touch is a press without a hover.
- **Disabled:** a disabled widget ignores both; `State` already draws it that way.
- **Layout:** hover and press change how a widget looks, never where it is.

## Keyboard focus

The app keeps a focus index over its controls; Tab and Shift-Tab move it, and Enter or Space act
on it. The focused widget gets `focused: true` and draws `focus_ring`. Settings already moves a
cursor over its rows, so it is the first to show the ring.

## Tests

- `Pointer`, in `theme_proofs`: hover, a press that begins and ends on one widget, a press
  dragged off, a release outside, and touch.
- Each app that gains hover: its proofs crate shows that a move inside one target asks for no
  repaint and a move to the next asks for one, where the app has a proofs crate.

## Open

- ❓ Whether the window manager tells an app the pointer left its window. If it does not, the
  last hover stays lit until the next event; a focus-loss frame could clear it.
