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

/*
 * NONOS Official Brand Colors
 * Source: nonos.systems/brand-guidelines
 *
 * Primary: #66FFFF (vibrant teal - innovation)
 * Secondary: #2E5C5C (dark teal - stability/credibility)
 * Typography: Poppins (Light, Regular, Medium, Semi Bold)
 */

/* primary brand accent - official vibrant teal */
pub const COLOR_ACCENT: u32 = 0xFF66FFFF;
pub const COLOR_ACCENT_DIM: u32 = 0xFF4DCCCC;
pub const COLOR_ACCENT_GLOW: u32 = 0x4066FFFF;

/* secondary brand color - official dark teal */
pub const COLOR_SECONDARY: u32 = 0xFF2E5C5C;
pub const COLOR_SECONDARY_DIM: u32 = 0xFF1E4040;

/* background colors - deep dark with teal undertone */
pub const COLOR_BG: u32 = 0xFF080C10;
pub const COLOR_BG_GRADIENT_TOP: u32 = 0xFF0A1014;
pub const COLOR_BG_GRADIENT_BOTTOM: u32 = 0xFF050808;

/* panel colors - subtle dark panels with depth */
pub const COLOR_PANEL: u32 = 0xFF0E1418;
pub const COLOR_PANEL_HOVER: u32 = 0xFF141C22;
pub const COLOR_PANEL_ACTIVE: u32 = 0xFF0A0E12;
pub const COLOR_PANEL_BORDER: u32 = 0xFF1A2428;

/* text colors - teal accent for primary, white for readable */
pub const COLOR_TEXT: u32 = 0xFF66FFFF;
pub const COLOR_TEXT_WHITE: u32 = 0xFFF0F6FC;
pub const COLOR_TEXT_DIM: u32 = 0xFF6E8088;
pub const COLOR_TEXT_MUTED: u32 = 0xFF3A4448;

/* terminal colors - dark immersive terminal */
pub const COLOR_TERMINAL_BG: u32 = 0xFF0A0E12;
pub const COLOR_TERMINAL_BORDER: u32 = 0xFF1A2428;

/* semantic colors - consistent with brand */
pub const COLOR_GREEN: u32 = 0xFF00E676;
pub const COLOR_RED: u32 = 0xFFFF5252;
pub const COLOR_YELLOW: u32 = 0xFFFFD740;
pub const COLOR_ORANGE: u32 = 0xFFFF9100;
pub const COLOR_PURPLE: u32 = 0xFFBB86FC;

/* ui state colors */
pub const COLOR_SUCCESS: u32 = 0xFF00E676;
pub const COLOR_ERROR: u32 = 0xFFFF5252;
pub const COLOR_WARNING: u32 = 0xFFFFD740;
pub const COLOR_INFO: u32 = 0xFF66FFFF;

/* cursor and selection - brand teal */
pub const COLOR_CURSOR: u32 = 0xFF66FFFF;
pub const COLOR_SELECTION: u32 = 0x4066FFFF;

/* grid and subtle elements */
pub const COLOR_GRID: u32 = 0xFF0C1014;
pub const COLOR_GRID_ACCENT: u32 = 0xFF101820;
pub const COLOR_GLOW_SOFT: u32 = 0x1866FFFF;

/* legacy/compatibility aliases */
pub const COLOR_FG: u32 = COLOR_TEXT;
pub const COLOR_WHITE: u32 = 0xFFFFFFFF;
pub const COLOR_BLACK: u32 = 0xFF000000;
pub const COLOR_BLUE: u32 = COLOR_ACCENT;
pub const COLOR_GRAY: u32 = 0xFF707070;
pub const COLOR_DARK_GRAY: u32 = 0xFF383838;
pub const COLOR_LIGHT_GRAY: u32 = 0xFFB0B0B0;
pub const COLOR_MENU_BG: u32 = COLOR_PANEL;
pub const COLOR_DOCK_BG: u32 = COLOR_PANEL;
pub const COLOR_WINDOW_BG: u32 = COLOR_PANEL;
pub const COLOR_TITLE_BG: u32 = COLOR_PANEL_ACTIVE;
pub const COLOR_TITLE_FG: u32 = COLOR_TEXT_WHITE;
