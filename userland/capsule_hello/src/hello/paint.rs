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
use nonos_toolkit::design::scale::scale;
use nonos_toolkit::design::size::SPACE;
use nonos_toolkit::design::text_role::TextRole;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Ink, Label, Rect};

/// The window's ground and accent bar, then four labels stacked from the top,
/// each as tall as its own line, so the text sizes and spacing follow the
/// display's scale and the colours follow the theme.
pub fn paint(fb: &mut PaintBuffer) {
    let (r, s) = (roles(), scale());
    let space = |gap: u16| s.px(u32::from(gap));
    fb.clear(r.bg.argb());
    fb.fill_rect(0, 0, fb.width, space(SPACE.xs), r.accent.argb());
    let lines = [
        Label::new("hello, NONOS").role(TextRole::Headline).ink(Ink::Accent),
        Label::new("a signed, attested capsule"),
        Label::new("built from the quickstart"),
        Label::new("press Esc to close").ink(Ink::Quiet),
    ];
    let (x, w) = (space(SPACE.xl), fb.width.saturating_sub(space(SPACE.xl) * 2));
    let mut y = x;
    for label in lines {
        let h = label.size().1;
        label.draw(fb, Rect { x, y, w, h });
        y += h + space(SPACE.sm);
    }
}
