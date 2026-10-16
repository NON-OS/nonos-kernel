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

//! The four-bar equalizer that replaces the index on a playing row.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::derive::with_alpha;
use nonos_toolkit::theme::roles;

use crate::ui::geometry::Rect;
use crate::ui::paint::fill;

/// Output levels, of 32767, at which each bar lights: about -24, -18, -12
/// and -6 dB.
const LIT_AT: [u16; 4] = [2064, 4125, 8231, 16423];

/// The playing row's level meter: four bars, rising left to right, lit by
/// the loudest sample just sent to the output (`Transport::level`). It was
/// animated from a frame counter, the same dance whatever was playing and
/// through silence.
pub fn equalizer(fb: &mut PaintBuffer, r: Rect, level: u16) {
    let bw = (r.w / 7).max(2);
    let gap = (r.w - bw * 4) / 3;
    let accent = roles().accent.argb();
    for (i, at) in LIT_AT.iter().enumerate() {
        let h = (r.h * (i as i32 + 1) / 4).max(2);
        let x = r.x + i as i32 * (bw + gap);
        let ink = if level >= *at { accent } else { with_alpha(accent, 0x40) };
        fill(fb, Rect::new(x, r.bottom() - h, bw, h), 1, ink);
    }
}
