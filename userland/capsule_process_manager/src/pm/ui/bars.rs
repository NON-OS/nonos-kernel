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
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Progress, Rect, State as Look, Tone};

use super::metrics::{BAR_H, BAR_ROW_H, BODY_PX, NUM_PX};
use super::text;

pub const BAR_GAP: u32 = 12;

// The one horizontal meter every screen draws, so CPU, Memory and Authority
// cannot drift apart: the toolkit's bar in the box given. The caller passes a
// numerator and a denominator instead of a fraction because this capsule keeps
// floats out of its paint path. A resident figure in kb reaches ~4e9, past
// what the bar counts in, so both are shifted down together until the
// denominator fits. A bar has no muted fill, so a plain tone draws as the
// bar's disabled fill, the one grey it has.
pub fn hbar(fb: &mut PaintBuffer, x: u32, y: u32, w: u32, h: u32, num: u64, den: u64, tone: Tone) {
    let shift = (u64::BITS - den.leading_zeros()).saturating_sub(u32::BITS);
    let (done, total) = ((num.min(den) >> shift) as u32, (den >> shift) as u32);
    let look = Look { disabled: tone == Tone::Plain, ..Look::default() };
    Progress::new(done, total).tone(tone).state(look).draw(fb, Rect { x, y, w, h });
}

// A whole bar row: label cut to a third of the width, the meter across the
// middle, and the value placed from the right edge so a column of them lines up
// on its last digit.
pub fn labelled(
    fb: &mut PaintBuffer,
    x: u32,
    y: u32,
    w: u32,
    label: &[u8],
    value: &[u8],
    num: u64,
    den: u64,
    tone: Tone,
) {
    let val_w = text::mono_width(fb, value, NUM_PX);
    let label_w = (w / 3).min(w.saturating_sub(val_w + BAR_GAP * 2));
    let (r, top) = (roles(), text::centred_top(y, BAR_ROW_H, BODY_PX));
    let cut = text::fit(fb, label, BODY_PX, label_w);
    text::left(fb, x, top, cut, r.text_2, BODY_PX);
    text::mono_right(fb, x + w, top, value, tone.colour(&r), NUM_PX);
    let bar_w = w.saturating_sub(label_w + val_w + BAR_GAP * 2);
    let bar_y = y + BAR_ROW_H.saturating_sub(BAR_H) / 2;
    hbar(fb, x + label_w + BAR_GAP, bar_y, bar_w, BAR_H, num, den, tone);
}
