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

//! Pill chips for filters, genres and metadata stamps.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::ui::geometry::Rect;
use crate::ui::metrics::{pill, LABEL, S4};
use crate::ui::paint::{panel, text_centre, width};

pub fn measure(label: &str) -> i32 {
    width(label, LABEL) + S4 * 2
}

pub fn chip(fb: &mut PaintBuffer, r: Rect, label: &str, pressed: bool) {
    let t = roles();
    let (bg, border, fg) = if pressed {
        (t.accent_wash.argb(), t.accent.argb(), t.accent.argb())
    } else {
        (t.raised.argb(), t.border.argb(), t.text_2.argb())
    };
    panel(fb, r, pill(r.h), bg, border);
    text_centre(fb, r, label, fg, LABEL);
}

pub fn stamp(fb: &mut PaintBuffer, r: Rect, label: &str) {
    let t = roles();
    panel(fb, r, pill(r.h), t.bg.argb(), t.border.argb());
    text_centre(fb, r, label, t.accent.argb(), LABEL);
}
