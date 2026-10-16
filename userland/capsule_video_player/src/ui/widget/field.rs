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
use crate::ui::icon::ui::search;
use crate::ui::layout::Rect;
use crate::ui::paint::rrect;
use crate::ui::text::{center_y, BODY_PX};

const ICON: u32 = 16;
const TEXT_X: u32 = 36;
const CARET_W: u32 = 2;

pub fn paint_field(fb: &mut PaintBuffer, r: Rect, placeholder: &str, value: &str, focus: bool) {
    let theme = roles();
    let border = if focus { theme.accent } else { theme.border }.argb();
    rrect::panel(fb, r.x, r.y, r.w, r.h, 9, theme.surface.argb(), border);
    search(fb, r.x + 12, r.y + r.h.saturating_sub(ICON) / 2, ICON, theme.muted.argb());
    let room = r.w.saturating_sub(TEXT_X + 14);
    let y = center_y(r.y, r.h);
    if value.is_empty() {
        let ghost = fit(placeholder, room, BODY_PX);
        fb.text_ttf((r.x + TEXT_X) as i32, y, ghost, theme.quiet.argb(), BODY_PX);
        return;
    }
    let shown = fit(value, room.saturating_sub(CARET_W + 2), BODY_PX);
    let end = fb.text_ttf((r.x + TEXT_X) as i32, y, shown, theme.text.argb(), BODY_PX);
    if focus {
        let caret = theme.accent.argb();
        fb.fill_rect(end.max(0) as u32 + 2, r.y + 9, CARET_W, r.h.saturating_sub(18), caret);
    }
}
