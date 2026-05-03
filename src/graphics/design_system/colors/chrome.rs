// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::display::framebuffer::colors as brand;

pub const TITLEBAR_BG: u32 = brand::COLOR_PANEL;
pub const TITLEBAR_BG_UNFOCUSED: u32 = brand::COLOR_PANEL_ACTIVE;
pub const TITLEBAR_TEXT: u32 = brand::COLOR_TEXT_WHITE;
pub const TITLEBAR_TEXT_UNFOCUSED: u32 = brand::COLOR_TEXT_DIM;
pub const WINDOW_BG: u32 = brand::COLOR_PANEL;
pub const WINDOW_BORDER: u32 = brand::COLOR_PANEL_BORDER;
pub const WINDOW_BTN_CLOSE: u32 = 0xFFFF5F57;
pub const WINDOW_BTN_MINIMIZE: u32 = 0xFFFEBC2E;
pub const WINDOW_BTN_MAXIMIZE: u32 = 0xFF28C840;
pub const SCROLLBAR_TRACK: u32 = 0xFF141820;
pub const SCROLLBAR_THUMB: u32 = 0xFF3A4448;
pub const SCROLLBAR_THUMB_HOVER: u32 = 0xFF4A5458;
pub const DOCK_BG: u32 = 0xE8101418;
pub const DOCK_ACCENT: u32 = 0xFF00D4FF;
pub const DOCK_INDICATOR: u32 = brand::COLOR_ACCENT;
pub const MENUBAR_BG: u32 = 0xE0080C10;
pub const MENU_HOVER: u32 = brand::COLOR_ACCENT;
