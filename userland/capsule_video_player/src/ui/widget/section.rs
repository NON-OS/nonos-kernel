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

use crate::ui::fit::right_x;
use crate::ui::text::{BODY_PX, TITLE_PX};

pub fn paint_head(fb: &mut PaintBuffer, x: u32, y: u32, w: u32, title: &str, action: &str) {
    let r = roles();
    fb.text_ttf(x as i32, y as i32, title, r.text.argb(), TITLE_PX);
    if !action.is_empty() {
        let ax = right_x(action, x + w, BODY_PX);
        fb.text_ttf(ax, (y + 4) as i32, action, r.accent.argb(), BODY_PX);
    }
}

pub fn paint_label(fb: &mut PaintBuffer, x: u32, y: u32, label: &str) {
    fb.text_ttf(x as i32, y as i32, label, roles().muted.argb(), BODY_PX);
}
