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

use nonos_app_skeleton::paint::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::ui::fit::fit;
use crate::ui::icon;
use crate::ui::layout::{Rect, PAD, TOP};
use crate::ui::text::{center_y, TITLE_PX};

pub const HEADER_H: u32 = 46;
const ARROW: u32 = 18;
const TITLE_X: u32 = PAD + ARROW + 14;

pub fn back_button() -> Rect {
    let side = ARROW + 12;
    Rect { x: PAD.saturating_sub(6), y: TOP + (HEADER_H - side) / 2, w: side, h: side }
}

pub fn info_button(w: u32) -> Rect {
    Rect { x: w.saturating_sub(PAD + 30), y: TOP + 8, w: 30, h: 30 }
}

pub fn paint_header(fb: &mut PaintBuffer, w: u32, title: &str) {
    let r = roles();
    fb.fill_rect(0, TOP, w, HEADER_H, r.bg.argb());
    let b = back_button();
    icon::ui::back(fb, PAD, b.y + 6, ARROW, r.muted.argb());
    let i = info_button(w);
    icon::ui::info(fb, i.x + 7, i.y + 7, 16, r.muted.argb());
    let room = w.saturating_sub(TITLE_X + PAD + i.w + 12);
    let shown = fit(title, room, TITLE_PX);
    fb.text_ttf(TITLE_X as i32, center_y(TOP, HEADER_H), shown, r.text.argb(), TITLE_PX);
}
