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
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Card, Rect};

use crate::calc::convert::{convert, list};
use crate::calc::error_kind::ErrorKind;
use crate::calc::format::{error_text, format, DISPLAY_MAX};
use crate::calc::state::State;
use crate::calc::ui::convert_geom::result;
use crate::calc::ui::metrics::PX_BODY;
use crate::calc::ui::trim::trim;

const LADDER: [f32; 3] = [34.0, 26.0, 17.0];
const PAD: i32 = 14;

fn fit(fb: &PaintBuffer, text: &str, budget: i32) -> f32 {
    for px in LADDER.iter() {
        if fb.measure_ttf(text, *px) <= budget {
            return *px;
        }
    }
    LADDER[LADDER.len() - 1]
}

fn pair(state: &State, fb: &mut PaintBuffer, x: i32, y: i32, budget: i32) {
    let units = list(state.cat);
    let src = units.get(state.from).map(|unit| unit.name).unwrap_or("");
    let dst = units.get(state.to).map(|unit| unit.name).unwrap_or("");
    let (head, _) = trim(fb, src, budget, PX_BODY);
    let muted = roles().muted.argb();
    let mut cursor = fb.text_ttf(x, y, head, muted, PX_BODY);
    cursor = fb.text_ttf(cursor, y, " to ", muted, PX_BODY);
    let (tail, _) = trim(fb, dst, budget, PX_BODY);
    fb.text_ttf(cursor, y, tail, muted, PX_BODY);
}

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let (x, y, w, h) = result(fb.width as i32, fb.height as i32);
    if w <= PAD * 2 || h <= 0 || x < 0 || y < 0 {
        return;
    }
    Card::new().draw(fb, Rect { x: x as u32, y: y as u32, w: w as u32, h: h as u32 });
    let r = roles();
    pair(state, fb, x + PAD, y + PAD, w / 3);
    let mut buf = [0u8; DISPLAY_MAX];
    let (text, ink) = match convert(state.cat, state.from, state.to, state.display) {
        Some(value) => {
            let n = format(value, 0, &mut buf);
            (core::str::from_utf8(&buf[..n]).unwrap_or("0"), r.accent)
        }
        /* The units are fixed tables, so the only way a conversion fails is a
         * product past what the fixed point holds. */
        None => (error_text(ErrorKind::Overflow), r.danger),
    };
    let px = fit(fb, text, w / 2);
    let tx = x + w - PAD - fb.measure_ttf(text, px);
    fb.text_ttf(tx, y + (h - line_height(px).max(1)) / 2, text, ink.argb(), px);
}
