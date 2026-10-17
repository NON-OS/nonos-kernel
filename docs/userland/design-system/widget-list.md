# Widget list

Version 1 holds the widgets that five or more apps build for themselves today. It also has
`Label`, which every screen needs, and the widgets the first three apps to move need:
Settings' `Switch` and `Slider`, App Store's and Process Manager's `Scrollbar`, and Process
Manager's `Progress`. Sizes are from [Sizes](sizes.md). Every widget also takes
`.state(State)`, which is not repeated below.

## Version 1

| Widget | `new` | Builders | `hit` returns | Draws |
|---|---|---|---|---|
| `Label` | `(text)` | `.role(Body/Title/Headline)`, `.ink(Ink)`, `.align(Left/Centre/Right)` | none | one line, truncated to `at` |
| `Card` | `()` | `.title(&str)`, `.note(&str)` | `bool` | `surface`, `border`, `card` radius; `content` is the area under its head |
| `SectionHeader` | `(title)` | `.note(&str)` | none | a title over its rows |
| `Separator` | `()` | `.soft()` | none | a `border` or `border_soft` hairline |
| `Row` | `(label)` | `.value(&str)`, `.value_ink(Ink)`, `.note(&str)`, `.chevron()`, `.trailing(w)` | `bool` | label left, value right, note below; `trailing_rect` is the room for an app's control |
| `Button` | `(label)` | `.kind(Primary/Secondary/Plain/Danger)` | `bool` | a `control`-radius button |
| `Field` | `(text)` | `.icon(IconId)`, `.placeholder(&str)`, `.caret(Option<usize>)` | `bool` | text or placeholder; shows the tail when long |
| `Tabs` | `(&[&str], selected)` | `.hovered(Option<usize>)` | `Option<usize>` | a segmented strip |
| `NavItem` | `(label)` | `.icon(IconId)`, `.active(bool)` | `bool` | a sidebar entry |
| `Pill` | `(label)` | `.tone(Tone)`, `.dot()` | `bool` | a `pill`-radius chip |
| `Progress` | `(done, total)` | `.tone(Tone)` | none | a bar filled `done / total` |
| `Switch` | `(on)` | none | `bool` | the switch from Settings' `ui/switch.rs` |
| `Slider` | `(value, max)` | none | `Option<u32>`, the value at `x` | track and knob |
| `Scrollbar` | `(offset, content, viewport)` | none | `Option<u32>`, the offset at `y` | a thin thumb in a track |

`Ink` names a text role: `Text`, `Text2`, `Muted`, `Quiet`, `Accent`, `Ok`, `Warn`, `Danger`.
`Tone` names a status: `Plain`, `Accent`, `Ok`, `Warn`, `Danger`. An app chooses the meaning,
and the theme supplies the colour.

## Version 2, built

The rest of [Widgets, version 2](widgets-v2.md) joins this table as each one lands.

| Widget | `new` | Builders | `hit` returns | Draws |
|---|---|---|---|---|
| `Column` | `(at)` | `.gap(u32)` | none | nothing; `next(h)` and `rest()` hand out `Rect`s down `at` |
| `Checkbox` | `(on)` | `.label(&str)` | `bool` | a 20 px box, a tick when on, its label right of it |
| `Radio` | `(selected)` | `.label(&str)` | `bool` | a 20 px ring, a dot when selected, its label right of it |
| `IconButton` | `(IconId)` | `.kind(Kind)`, `.label(&str)` | `bool` | an 18 px icon in a 36 px square, or beside its label; the body is a `Button` |
| `Tooltip` | `(text)` | `.below()` | none; `place(anchor, bounds)` gives its `Rect` | one line on `raised`, cut with `…` past 320 px, with a drop shadow inside its box |
| `Toast` | `(text)` | `.tone(Tone)`, `.action(&str)` | `bool`, the action | a `raised` panel up to 360 px with a tone bar, two lines of text and a `Plain` action `Button` |

## Later

[Widgets, version 2](widgets-v2.md) specifies every one of these, and adds `Toast`.

| Widget | Apps today | Why later |
|---|---|---|
| `Menu` | 3 | needs a popup surface and outside-click handling |
| `Table` | 2 | Process Manager's 7 table files; wants a column model |
| `Dialog` | 1, the desktop shell | needs focus between buttons |

Settings' `chevron.rs` becomes `Row::chevron()`, not a widget of its own.

## A first screen

```rust
use nonos_toolkit::widgets::{Card, Rect, Row, Switch};

fn paint(&mut self, fb: &mut PaintBuffer) {
    let card = Rect { x: 16, y: 16, w: 420, h: 98 };
    Card::new().title("Network").draw(fb, card);
    Row::new("Wi-Fi").draw(fb, self.wifi_row());
    Switch::new(self.wifi).draw(fb, self.wifi_switch());
}
```
