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

pub const MAX_URL_LEN: usize = 256;
pub const MAX_CONTENT_LINES: usize = 512;
pub const MAX_LINE_LEN: usize = 256;
pub const MAX_HISTORY: usize = 64;
pub const MAX_STATUS_LEN: usize = 64;
pub const MAX_TITLE_LEN: usize = 64;

pub const TOOLBAR_HEIGHT: u32 = 40;
pub const STATUS_BAR_HEIGHT: u32 = 25;
pub const BUTTON_WIDTH: u32 = 25;
pub const BUTTON_HEIGHT: u32 = 24;
pub const BUTTON_PADDING: u32 = 8;
pub const URL_BAR_PADDING: u32 = 8;
pub const CONTENT_PADDING: u32 = 12;

pub const COLOR_TOOLBAR_BG: u32 = 0xFF21262D;
pub const COLOR_BUTTON_ACTIVE: u32 = 0xFF2D333B;
pub const COLOR_BUTTON_INACTIVE: u32 = 0xFF1A1D21;
pub const COLOR_URL_BAR_BG: u32 = 0xFF0D1117;
pub const COLOR_URL_BAR_BORDER: u32 = 0xFF3D444B;
pub const COLOR_CONTENT_BG: u32 = 0xFF0D1117;
pub const COLOR_STATUS_BG: u32 = 0xFF21262D;
pub const COLOR_SCROLLBAR_BG: u32 = 0xFF21262D;
pub const COLOR_SCROLLBAR_THUMB: u32 = 0xFF4A5058;
pub const COLOR_STATUS_TEXT: u32 = 0xFF7D8590;
pub const COLOR_DISABLED: u32 = 0xFF4A5058;

pub const HTTP_TIMEOUT_MS: u64 = 20_000;
pub const MAX_RESPONSE_SIZE: usize = 5 * 1024 * 1024;
