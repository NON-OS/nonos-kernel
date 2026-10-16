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
use nonos_toolkit::widgets::Tone;

use crate::pm::format;
use crate::pm::security::sensitive::{ADMIN, DEBUG, RAW_HW, SPAWN};

use super::metrics::{NUM_PX, RISK_SLOT_GAP, RISK_SLOT_H, RISK_SLOT_W};
use super::text;

// The four sensitive classes, in the order a row prints them, each with the
// tone it is drawn in: admin danger, raw hardware warn, spawn accent and debug
// the plain, muted tone.
pub const CLASSES: [(u64, Tone); 4] =
    [(ADMIN, Tone::Danger), (RAW_HW, Tone::Warn), (SPAWN, Tone::Accent), (DEBUG, Tone::Plain)];

// One letter per class, in the class colour when held and in border_strong,
// the track colour, when not, at a fixed advance so a scanning eye compares
// rows by position.
// Admin, raw Hardware, Spawn, Debug.
const LETTERS: [&[u8]; 4] = [b"A", b"H", b"S", b"D"];

pub fn paint(fb: &mut PaintBuffer, x: u32, y: u32, caps: u64) -> u32 {
    let (r, top) = (roles(), text::centred_top(y, RISK_SLOT_H, NUM_PX));
    let mut slot_x = x;
    for (i, (mask, tone)) in CLASSES.iter().enumerate() {
        let ink = if caps & mask != 0 { tone.colour(&r) } else { r.border_strong };
        text::mono(fb, slot_x, top, LETTERS[i], ink, NUM_PX);
        slot_x += RISK_SLOT_W + RISK_SLOT_GAP;
    }
    let mut buf = [0u8; 4];
    let n = format::u32_decimal(caps.count_ones(), &mut buf);
    text::mono(fb, slot_x + RISK_SLOT_GAP, top, &buf[..n], r.muted, NUM_PX);
    slot_x + RISK_SLOT_GAP + text::mono_width(fb, &buf[..n], NUM_PX)
}
