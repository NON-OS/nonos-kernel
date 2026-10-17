// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::font::ttf::line_height;
use nonos_toolkit::theme::{roles, Opaque};
use nonos_toolkit::widgets::text::{centre, centre_top, left, truncate, width};
use nonos_toolkit::widgets::Rect;

use super::card;
use super::metrics::{
    BODY_PX, CARD_PAD, TILE_H, TILE_RING_R, TILE_RING_T, TILE_RING_TOP, TILE_SUB_GAP, VALUE_PX,
};
use super::mono::valid;

pub const HEIGHT: u32 = TILE_H;

// A ring, the value it stands for, and one line of provenance under it. The
// arc and the track share a centre and a radius, so the filled sweep is always
// exactly the fraction `num/den` of the ring the eye compares it against.
pub fn tile(
    fb: &mut PaintBuffer,
    x: u32,
    y: u32,
    w: u32,
    label: &[u8],
    value: &[u8],
    sub: &[u8],
    num: u64,
    den: u64,
) {
    let r = roles();
    card::panel(fb, x, y as i32, w, TILE_H);
    let cx = x + w / 2;
    let cy = y + TILE_RING_TOP + TILE_RING_R;
    fb.ring(cx, cy, TILE_RING_R, TILE_RING_T, r.border_strong.argb());
    fb.ring_arc(cx, cy, TILE_RING_R, TILE_RING_T, num, den.max(1), r.accent.argb());
    let value_top = centre_top(cy - TILE_RING_R, TILE_RING_R * 2, VALUE_PX);
    let value_w = width(valid(value), VALUE_PX);
    left(fb, cx.saturating_sub(value_w / 2), value_top, valid(value), r.text, VALUE_PX);
    let inner = card::inner(w);
    let label_y = cy + TILE_RING_R + CARD_PAD;
    label_line(fb, x, label_y, inner, label, r.text);
    let step = line_height(BODY_PX).max(1) as u32 + TILE_SUB_GAP;
    label_line(fb, x, label_y + step, inner, sub, r.muted);
}

// Both lines under the ring are centred on the card, which means measuring the
// cut string rather than the original: a truncated label centres on what is
// actually drawn.
fn label_line(fb: &mut PaintBuffer, x: u32, y: u32, inner: u32, bytes: &[u8], ink: Opaque) {
    let cut = truncate(valid(bytes), inner, BODY_PX);
    let area = Rect { x: x + CARD_PAD, y, w: inner, h: 0 };
    centre(fb, area, y as i32, &cut, ink, BODY_PX);
}
