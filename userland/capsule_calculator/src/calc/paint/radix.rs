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
use nonos_toolkit::widgets::{Card, Rect};

use crate::calc::prog::{write, BASES, RADIX_MAX};
use crate::calc::state::State;
use crate::calc::ui::metrics::PX_MONO;
use crate::calc::ui::radix_geom::{origin, row_y, size, PAD};

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let (x, y) = origin();
    let (w, h) = size(fb.width as i32);
    if w <= 0 || h <= 0 {
        return;
    }
    Card::new().draw(fb, Rect { x: x as u32, y: y as u32, w: w as u32, h: h as u32 });
    let r = roles();
    let mut buf = [0u8; RADIX_MAX];
    for (i, base) in BASES.iter().enumerate() {
        let active = state.base == *base;
        let (tag, ink) = if active { (r.accent, r.accent) } else { (r.muted, r.text_2) };
        let ty = row_y(i);
        fb.text_ttf_mono(x + PAD, ty, base.label(), tag.argb(), PX_MONO);
        let n = write(state.prog, *base, &mut buf);
        let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
        let tx = x + w - PAD - fb.measure_ttf_mono(text, PX_MONO);
        fb.text_ttf_mono(tx, ty, text, ink.argb(), PX_MONO);
    }
}
