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

use crate::clock::tabs::{self, Tab, BAR_H, BAR_TOP};

pub fn paint(tab: Tab, fb: &mut PaintBuffer, width: u32) {
    let (w, r) = (width / 4, roles());
    for (i, t) in tabs::all().iter().enumerate() {
        let x = i as u32 * w;
        let active = *t == tab;
        let bg = if active { r.accent } else { r.bg };
        fb.fill_rect(x, BAR_TOP as u32, w, BAR_H as u32, bg.argb());
        let fg = if active { r.on_accent } else { r.muted };
        fb.text(x + 10, (BAR_TOP + 10) as u32, tabs::label(*t), fg.argb());
    }
}
