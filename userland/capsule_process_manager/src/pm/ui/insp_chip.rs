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

//! One grant chip, and the "+N more" chip that counts those without room.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::widgets::{Pill, Rect, Tone};

use crate::pm::format::u32_decimal;

use super::metrics::{BODY_PX, CHIP_H, CHIP_PAD_X};
use super::text;

/// The toolkit pill in the chip's box, which is exactly as wide as `chip_w`.
pub(super) fn chip(fb: &mut PaintBuffer, x: u32, y: u32, label: &[u8], tone: Tone) {
    let at = Rect { x, y, w: chip_w(fb, label), h: CHIP_H };
    Pill::new(text::valid(label)).tone(tone).draw(fb, at);
}

pub(super) fn chip_w(fb: &PaintBuffer, label: &[u8]) -> u32 {
    text::width(fb, label, BODY_PX) + CHIP_PAD_X * 2
}

pub(super) fn more_w(fb: &PaintBuffer, count: u32) -> u32 {
    let mut buf = [0u8; 16];
    let n = more(count, &mut buf);
    chip_w(fb, &buf[..n])
}

/// "+3 more".
pub(super) fn more(count: u32, out: &mut [u8; 16]) -> usize {
    out[0] = b'+';
    let n = 1 + u32_decimal(count, &mut out[1..]);
    out[n..n + 5].copy_from_slice(b" more");
    n + 5
}
