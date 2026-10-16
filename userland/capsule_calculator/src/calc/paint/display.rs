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
use nonos_toolkit::theme::derive::with_alpha;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Card, Rect};

use crate::calc::format::{error_text, format, DISPLAY_MAX};
use crate::calc::mode::Mode;
use crate::calc::op::Op;
use crate::calc::prog::{write, Bitwise, RADIX_MAX};
use crate::calc::state::State;
use crate::calc::ui::metrics::{PX_BODY, PX_RESULT};
use crate::calc::ui::readout_geom::{inset, origin, size};

const LADDER: [f32; 5] = [PX_RESULT, 44.0, 34.0, 26.0, 17.0];

fn eyebrow(op: Op) -> &'static str {
    match op {
        Op::None => "",
        Op::Add => "+",
        Op::Sub => "-",
        Op::Mul => "x",
        Op::Div => "/",
        Op::Pow => "^",
    }
}

fn pending(state: &State) -> &'static str {
    if state.mode != Mode::Programmer {
        return eyebrow(state.operator);
    }
    match state.prog_op {
        Some(Bitwise::And) => "AND",
        Some(Bitwise::Or) => "OR",
        Some(Bitwise::Xor) => "XOR",
        _ => "",
    }
}

fn fit(fb: &PaintBuffer, text: &str, budget: i32) -> f32 {
    for px in LADDER.iter() {
        if fb.measure_ttf(text, *px) <= budget {
            return *px;
        }
    }
    LADDER[LADDER.len() - 1]
}

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let (ox, oy) = origin();
    let (w, h) = size(fb.width as i32);
    if w <= 0 || h <= 0 {
        return;
    }
    let (ux, uy, uw, uh) = (ox as u32, oy as u32, w as u32, h as u32);
    let theme = roles();
    Card::new().draw(fb, Rect { x: ux, y: uy, w: uw, h: uh });
    fb.gradient_v(ux + 1, uy + 1, uw - 2, uh - 2, 0, with_alpha(theme.bg.argb(), 0x80));
    let pad = inset();
    fb.text_ttf(ox + pad, oy + pad, pending(state), theme.muted.argb(), PX_BODY);
    if state.memory_engaged() {
        let mx = ox + w - pad - fb.measure_ttf("M", PX_BODY);
        fb.text_ttf(mx, oy + pad, "M", theme.warn.argb(), PX_BODY);
    }
    let mut buf = [0u8; DISPLAY_MAX];
    let mut rbuf = [0u8; RADIX_MAX];
    let n = format(state.display, state.decimal_digits_typed, &mut buf);
    let r = write(state.prog, state.base, &mut rbuf);
    let (text, ink) = if state.is_error() {
        (error_text(state.error), theme.danger)
    } else if state.mode == Mode::Programmer {
        (core::str::from_utf8(&rbuf[..r]).unwrap_or("0"), theme.text)
    } else {
        (core::str::from_utf8(&buf[..n]).unwrap_or("Error"), theme.text)
    };
    let px = fit(fb, text, w - pad * 2);
    let vx = ox + w - pad - fb.measure_ttf(text, px);
    let vy = oy + h - pad - line_height(px).max(1);
    fb.text_ttf(vx, vy, text, ink.argb(), px);
}
