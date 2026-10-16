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

//! What the manager actually knows about permissions is one bit: `stat_full`
//! reports writable or not, and only for files -- `refresh_meta` skips
//! directories, so a directory's bit is the `true` it was built with. There is
//! no owner, group or mode in the reply, so this block states the bit and the
//! octal mode the toggle will write, and claims nothing else.

extern crate alloc;

use alloc::string::String;

use nonos_app_skeleton::{measure_ttf, PaintBuffer};
use nonos_toolkit::theme::roles;

use super::chrome_pill::{pill_r, PillState};
use super::entries::Entry;
use super::header_slots::{TOOL_H, TOOL_PAD, TOOL_PX};
use super::info_geom::InfoGeom;
use super::info_sizes::SEC_PX;
use super::layout::R_CARD;
use super::paint_tool_pill::text_y;
use super::perms::{MODE_RO, MODE_RW};

const HEADING: &str = "Permissions";

/// The label the toggle carries, which names both the direction and the mode it
/// will chmod to, because the store reports no mode of its own.
pub fn perm_label(writable: bool) -> String {
    let (verb, mode) =
        if writable { ("read-only", MODE_RO) } else { ("writable", MODE_RW) };
    alloc::format!("Make {verb} ({mode:04o})")
}

/// The pill's width, measured off the free function so the hit-test matches.
pub fn perm_btn_w(writable: bool) -> u32 {
    measure_ttf(perm_label(writable).as_str(), TOOL_PX).max(0) as u32 + TOOL_PAD * 2
}

/// Drawn only when the panel has room, and the hit-test applies the same clip.
pub fn paint_perms(fb: &mut PaintBuffer, g: &InfoGeom, entry: &Entry) {
    if g.perms_btn + TOOL_H > g.bottom {
        return;
    }
    let muted = roles().muted.argb();
    let _ = fb.text_ttf(g.x as i32, g.perms_head as i32, HEADING, muted, SEC_PX);
    let w = perm_btn_w(entry.writable).min(g.w);
    pill_r(fb, g.x, g.perms_btn, w, TOOL_H, R_CARD, PillState::Idle);
    let label = perm_label(entry.writable);
    let pen = (g.x + TOOL_PAD) as i32;
    let _ = fb.text_ttf(pen, text_y(g.perms_btn), label.as_str(), muted, TOOL_PX);
}
