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

use crate::graphics::framebuffer::colors as brand;

pub const CALC_DISPLAY_BG: u32 = 0xFF1C1C1E;
pub const CALC_BTN_NUMBER: u32 = 0xFF505050;
pub const CALC_BTN_NUMBER_HOVER: u32 = 0xFF606060;
pub const CALC_BTN_OPERATOR: u32 = 0xFFFF9500;
pub const CALC_BTN_OPERATOR_HOVER: u32 = 0xFFFFAA33;
pub const CALC_BTN_EQUALS: u32 = 0xFF007AFF;
pub const CALC_BTN_FUNCTION: u32 = 0xFF3A3A3C;

pub const EDITOR_GUTTER_BG: u32 = 0xFF0A0E12;
pub const EDITOR_GUTTER_TEXT: u32 = 0xFF4A5458;
pub const EDITOR_LINE_HIGHLIGHT: u32 = 0xFF141820;
pub const EDITOR_SELECTION: u32 = 0xFF264F78;
pub const EDITOR_BG: u32 = 0xFF0D1117;
pub const EDITOR_MATCH: u32 = 0xFF3D4A3A;
pub const EDITOR_COMMENT: u32 = 0xFF5C6370;
pub const EDITOR_STRING: u32 = 0xFF98C379;
pub const EDITOR_NUMBER: u32 = 0xFFD19A66;

pub const SYNTAX_KEYWORD: u32 = 0xFFCF8DFB;
pub const SYNTAX_STRING: u32 = EDITOR_STRING;
pub const SYNTAX_NUMBER: u32 = EDITOR_NUMBER;
pub const SYNTAX_COMMENT: u32 = EDITOR_COMMENT;
pub const SYNTAX_FUNCTION: u32 = 0xFF61AFEF;
pub const SYNTAX_OPERATOR: u32 = 0xFFABB2BF;

pub const TERMINAL_BG: u32 = brand::COLOR_TERMINAL_BG;
pub const TERMINAL_TEXT: u32 = brand::COLOR_TEXT_WHITE;
pub const TERMINAL_PROMPT: u32 = brand::COLOR_ACCENT;

pub const WALLET_ACCENT: u32 = 0xFF6366F1;
pub const WALLET_PURPLE: u32 = 0xFFA855F7;
pub const WALLET_CYAN: u32 = 0xFF06B6D4;
pub const WALLET_CARD: u32 = 0xFF18181F;
pub const WALLET_SIDEBAR: u32 = 0xFF12121A;
