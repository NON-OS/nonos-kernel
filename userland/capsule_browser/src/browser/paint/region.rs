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

use crate::browser::ui::rect::Rect;

/// The part of `fb` under the layout rect `r`, its top left corner at
/// (0, 0): the toolbar and the page each paint into their own.
pub(super) fn region<'b>(fb: &'b mut PaintBuffer, r: Rect) -> PaintBuffer<'b> {
    let at = |v: i32| v.max(0) as u32;
    fb.sub(at(r.x), at(r.y), at(r.w), at(r.h))
}
