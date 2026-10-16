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

//! Painting and hit testing a scroll bar, both from `parts`.

use super::Scrollbar;
use crate::decorations::Rect;
use crate::paint::PaintBuffer;
use crate::theme::roles;
use crate::widgets::draw;
use crate::widgets::rect::{contains, share};

impl Scrollbar {
    /// Paints the thumb in `muted`, `text_2` when hovered and `text` when
    /// pressed. Disabled, or content that fits, draws nothing.
    pub fn draw(&self, fb: &mut PaintBuffer, at: Rect) {
        let (r, st) = (roles(), self.state);
        let Some(p) = self.parts(at) else {
            return;
        };
        if st.disabled {
            return;
        }
        let ink = if st.pressed {
            r.text
        } else if st.hovered {
            r.text_2
        } else {
            r.muted
        };
        draw::round(fb, p.thumb, p.radius, ink);
    }

    /// None outside `at` or when the content fits. Inside, the offset that
    /// puts the thumb's centre at `y`, clamped to 0..=most, so a click jumps
    /// there and a drag follows the pointer. A thumb that fills `at` has no
    /// travel and gives 0.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> Option<u32> {
        let p = self.parts(at)?;
        if !contains(at, x, y) {
            return None;
        }
        let down = u32::try_from(y).unwrap_or(0).saturating_sub(at.y);
        let top = down.saturating_sub(p.thumb.h / 2).min(p.travel);
        Some(share(top, p.most, p.travel))
    }
}
