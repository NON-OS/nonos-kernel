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

//! Why the selected listing can or cannot be installed: one row per gate.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{text, Ink, Rect, Row};

use crate::store::market::{Readiness, GATES};
use crate::store::verdict::Verdict;

use super::bytes::as_str;
use super::metrics::{DETAIL_PAD, GATE_ROW_H, SMALL_PX};

/// Paints and returns the y just below the last gate. The verdict itself is
/// the sentence above and the card's button, so it is not repeated here.
/// Each gate is a `Row` across the pane, which pads itself to the text
/// column `left` and `room` describe.
pub fn paint(fb: &mut PaintBuffer, left: u32, room: u32, mut top: i32, r: &Readiness) -> i32 {
    if Verdict::of(r) == Verdict::Installed {
        /* The package gate below will read as a failure. */
        let said = "in this image; nothing to fetch";
        text::left(fb, left, top, said, roles().muted, SMALL_PX);
        top += 24;
    }
    let (x, w) = (left.saturating_sub(DETAIL_PAD), room + DETAIL_PAD * 2);
    for (label, pass) in GATES.iter().zip(r.gates.iter()) {
        let (mark, ink) = if *pass { ("pass", Ink::Ok) } else { ("fail", Ink::Danger) };
        let at = Rect { x, y: top.max(0) as u32, w, h: GATE_ROW_H };
        Row::new(as_str(label)).value(mark).value_ink(ink).draw(fb, at);
        top += GATE_ROW_H as i32;
    }
    top
}
