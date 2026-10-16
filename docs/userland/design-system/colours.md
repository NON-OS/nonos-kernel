# Colours

## Seeds

A theme is a `Scheme` of 5 seeds: `bg`, `surface`, `accent`, `text`, `border`
(`toolkit/src/theme/schemes/mod.rs`). There are 8 schemes, in `THEME_LABELS` order, with Aurora as
the default. `theme_of(index, high_contrast)` picks one, or `HIGH_CONTRAST` when the flag is set.

Light becomes the ninth scheme and label. Its seeds come from the browser's light palette: bg
`0xFFF4F7FC`, surface `0xFFFFFFFF`, accent `0xFF2563EB`, text `0xFF13213A`, border `0xFFD9E2EF`.

## Roles

Widgets draw with roles. They never use a seed or a literal directly. `theme::roles()` returns a
`Roles` value (`Copy`) for the theme in force. Each role is worked out from the seeds, using
`derive::mix` (t out of 255) and `legible`. The formulas below reproduce what apps draw today.
`theme/chrome/` held an earlier set of these; nothing calls it, so it is left as it is.

| Role | Type | Used for | Worked out as |
|---|---|---|---|
| `bg` | opaque | window ground | seed |
| `sunken` | opaque | sidebar, header, status strip | `mix(bg, black, 12)` |
| `surface` | opaque | card, pane | seed |
| `inset` | opaque | table body, list inside a card | `mix(bg, surface, 128)` |
| `raised` | opaque | field, pill, selected card | `mix(surface, accent, 11)` |
| `border` | opaque | hairline | seed |
| `border_soft` | opaque | a line inside one surface | `mix(bg, border, 87)` |
| `border_strong` | opaque | control outline | `mix(border, text, 16)` |
| `text` | opaque | body and titles | seed |
| `text_2` | opaque | a value beside its label | `mix(text, bg, 36)`, stepped back to clear 4.5:1 on all four grounds |
| `muted` | opaque | secondary text | `mix(text, bg, MUTED_TARGET)`, stepped back the same way |
| `quiet` | opaque | placeholder, hint | `mix(text, bg, QUIET_TARGET)`, stepped back to clear 3:1 |
| `disabled` | opaque | an unavailable control | `mix(border, text, 57)` |
| `accent` | opaque | links, on states, the brand | seed |
| `accent_text` | opaque | an active tab or nav label | `mix(accent, text, 146)` |
| `on_accent` | opaque | ink on an accent fill | the first of `bg`, `text`, black, white to reach 4.5:1 |
| `accent_wash` | translucent | selected or active fill | `with_alpha(accent, 0x20)` |
| `accent_edge` | translucent | active outline | `with_alpha(accent, 0x59)` |
| `focus_ring` | translucent | keyboard focus | `with_alpha(accent, 0x80)` |
| `hover_wash` | translucent | hovered row | `with_alpha(text, 0x14)` |
| `ok`, `warn`, `danger` | opaque | status | fixed, from `theme/palette.rs` |
| `warn_soft` | opaque | warning banner | fixed: dark `0xFF3A2A0C`, light `0xFFFEF3C7` |
| `shadow` | translucent | drop shadow | fixed: dark `0x60000000`, light `0x30101828` |
| `scrim` | translucent | backing behind a label on the wallpaper | fixed: `0x8C060A0E` |

A colour only one widget needs, such as a switch's knob, is worked out inside that widget.

## Colour types

```rust
pub struct Opaque(u32);
pub struct Translucent(u32);
```

Both have `argb()`. `fill_rect` writes without blending, so it takes only an `Opaque`; a
`Translucent` goes through `blend_rect`, `fill_round` or `stroke_round`, which blend. That keeps
the dock-tile hole bug out of the widgets. Existing `paint` signatures do not change.

## Readability

`theme_proofs` checks every scheme, Light and high contrast included:

- 4.5:1 for `text`, `text_2` and `muted` on `bg`, `surface`, `sunken` and `raised`, and for
  `on_accent` on `accent`.
- 3:1 for `quiet` on all four grounds, since a placeholder sits on `raised`, and for `accent` on `bg`.
- `disabled`, borders and washes carry no floor. They are not read as text.

The `on_accent` rule exists for Solarized: its `bg` reads at only 4.08:1 on its accent. The
stepping back (`legible_walk::walk_on`) exists for it too: its text reads at only 4.86:1 on its
own surface, so a fixed step towards the ground would fail.

## What Light changes

The current schemes are all dark, and `theme/chrome/` assumes so. Its knob takes `text` as "the
lightest value there is". In Light that knob must take `on_accent` instead. `warn_soft` and
`shadow` take their light values. Light's border is 1.22:1 on its ground, which is acceptable
only because borders carry no floor.
