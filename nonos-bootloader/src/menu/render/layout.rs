// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::display::gop::get_dimensions;

pub const MARGIN: u32 = 40;
pub const PANEL_WIDTH: u32 = 320;
pub const ENTRY_H: u32 = 40;
pub const PAD: u32 = 20;

pub fn get_panel_bounds() -> (u32, u32, u32, u32) {
    let (sw, sh) = get_dimensions();
    (sw - PANEL_WIDTH - MARGIN, MARGIN, PANEL_WIDTH, sh - MARGIN * 2 - 60)
}
