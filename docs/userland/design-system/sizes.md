# Sizes and scale

Every size here is logical: 1 at a display scale of 1x. Sizes live in `nonos_toolkit::design`:
`size.rs` holds `SPACE` and the heights and radii below, `text_role.rs` the text sizes and
`scale.rs` the display scale. The widgets read them, and so does `capsule_hello`. The module's
older 4-role `color.rs` is to be retired.

## Spacing

`xs` 4, `sm` 8, `md` 12, `lg` 16, `xl` 24 (`design::SpacingScale`, unchanged).

## Radii

| Name | Value | Today |
|---|---|---|
| `control` | 8 | buttons and fields range from 2 to 10 |
| `card` | 12 | cards range from 0 (App Store) to 14; the window frame is 12 |
| `pill` | half the height | switches, pills, Settings' search field |

## Heights

| Widget | Height | From |
|---|---|---|
| row | 44, or 66 with a note | Settings `ROW_H` |
| nav item | 38 | Settings `NAV_H` |
| field, button | 36 | Browser `CTL_H` |
| tabs | 32 | App Store and Browser |
| pill | 26 | Settings `PILL_H` |
| switch | 24, and 42 wide | Settings |
| progress | 6 | Process Manager uses 7, the installer 2 units |
| scrollbar | 4 wide, thumb at least 18 | Process Manager |

## Text

| Role | px | Today |
|---|---|---|
| `Body` | 17 | almost all body text |
| `Title` | 21 | titles range from 18 to 26 |
| `Headline` | 26 | Settings' page title |

Text goes through `readable_px`, which raises anything below `MIN_UI_PX` (17.0) and then applies
the text-size setting (`font/ttf/text_scale.rs`). Smaller sizes asked for today, such as the
wallet's 10 to 16, already come out at 17. Line boxes come from `line_height`, and widths from
`measure_ttf`.

## Display scale

```rust
#[derive(Clone, Copy)]
pub struct Scale(u32);

impl Scale {
    pub fn px(self, logical: u32) -> u32;
    pub fn hair(self) -> u32;
    pub fn font(self, px: f32) -> f32;
}

pub fn scale() -> Scale;
pub fn set_scale(quarters: u32);
```

The scale is counted in quarters: 4 is 1x and 6 is 1.5x. `px` rounds `(v * q + 2) / 4`. `hair`
is the width of a hairline, `max(q / 4, 1)`, so it stays a whole pixel. `font` scales a text size
once, before `readable_px` floors it. The toolkit holds the value. `app_skeleton` sets it, since
the toolkit cannot depend on `app_skeleton`. A widget keeps logical sizes and converts them in
the one geometry function that its painter and its hit test share.

Version 1 keeps the scale at 4 in every app, so nothing on screen grows. Apps paint at 1x today,
and the compositor already gives large panels a canvas half their size
(`capsule_desktop_shell/src/state/scale.rs`). Scaling apps as well could double that. Turning it
on is a later step, measured on a boot. The rule picking quarters from the panel size,
`quarters_for`, exists twice: in `app_skeleton/src/runner/chrome.rs:86` and in
`capsule_install/brand/src/scale_rule.rs`.
