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

//! One binding: the key, then what it does.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use super::super::metrics::BODY_PX;
use super::super::text;
use super::geom::{KEY_W, ROW_H};

/// The key is drawn in a pill so a column of them reads as keys rather than as
/// the first word of each sentence.
pub fn paint(fb: &mut PaintBuffer, x: u32, y: u32, w: u32, key: &[u8], label: &[u8]) {
    let (r, cap_w) = (roles(), text::width(fb, key, BODY_PX) + 14);
    let cap_h = ROW_H.saturating_sub(4);
    fb.fill_round(x, y, cap_w.min(KEY_W), cap_h, 5, r.raised.argb());
    let top = text::centred_top(y, cap_h, BODY_PX);
    text::left(fb, x + 7, top, key, r.accent, BODY_PX);
    let text_x = x + KEY_W;
    let room = w.saturating_sub(KEY_W);
    let cut = text::fit(fb, label, BODY_PX, room);
    text::left(fb, text_x, top, cut, r.text_2, BODY_PX);
}
