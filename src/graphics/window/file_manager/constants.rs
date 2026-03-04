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

use crate::graphics::framebuffer::COLOR_ACCENT;

pub(crate) const MAX_ENTRIES: usize = 128;
pub(crate) const MAX_PATH_LEN: usize = 256;
pub(crate) const MAX_NAME_LEN: usize = 64;
pub(crate) const SIDEBAR_WIDTH: u32 = 130;
pub(crate) const ROW_HEIGHT: u32 = 28;
pub(crate) const HEADER_HEIGHT: u32 = 35;
pub(crate) const LIST_HEADER_HEIGHT: u32 = 25;
pub(crate) const STATUS_BAR_HEIGHT: u32 = 25;

pub(crate) const COLOR_SIDEBAR_BG: u32 = 0xFF161B22;
pub(crate) const COLOR_SIDEBAR_HEADER: u32 = 0xFF21262D;
pub(crate) const COLOR_SIDEBAR_SELECTED: u32 = 0xFF2D333B;
pub(crate) const COLOR_TEXT_DIM: u32 = 0xFF7D8590;
pub(crate) const COLOR_TEXT_LIGHT: u32 = 0xFFADBBC6;
pub(crate) const COLOR_PATH_BAR: u32 = 0xFF21262D;
pub(crate) const COLOR_LIST_HEADER: u32 = 0xFF1C2128;
pub(crate) const COLOR_ROW_ALT: u32 = 0xFF1A1F26;
pub(crate) const COLOR_ROW_SELECTED: u32 = 0xFF2D4A3A;
pub(crate) const COLOR_FOLDER: u32 = COLOR_ACCENT;
pub(crate) const COLOR_FILE: u32 = 0xFF7D8590;
