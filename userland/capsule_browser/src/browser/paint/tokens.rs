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

//! Every chrome colour, in one place. Painters name a token; none carries
//! an ARGB literal of its own.

pub const GROUND: u32 = 0xFFF4_F7FC;
pub const SURFACE: u32 = 0xFFFF_FFFF;
pub const SIDEBAR: u32 = 0xFFE8_EEF8;
pub const EDGE: u32 = 0xFFD9_E2EF;
pub const FIELD: u32 = 0xFFEE_F2F8;
pub const INK: u32 = 0xFF13_213A;
pub const INK2: u32 = 0xFF33_4460;
pub const MUTED: u32 = 0xFF5B_6B85;
pub const ACCENT: u32 = 0xFF25_63EB;
pub const ACCENT_SOFT: u32 = 0xFFDB_E7FF;
pub const ON_ACCENT: u32 = 0xFFFF_FFFF;
pub const SKY: u32 = 0xFFA9_CBFA;
pub const TEAL: u32 = 0xFF0E_7490;
pub const TEAL_SOFT: u32 = 0xFFDD_F6F8;
pub const DISABLED: u32 = 0xFFA9_B4C6;
pub const SHADOW: u32 = 0x3010_1828;
pub const WARN: u32 = 0xFFB4_5309;
pub const WARN_SOFT: u32 = 0xFFFE_F3C7;
/// Ink on the window frame, which the titlebar tab strip sits on.
pub const ON_FRAME: u32 = nonos_toolkit::decorations::TITLE_TEXT;

/// Letter tiles take one of these, picked by a hash of the site.
pub const TILES: [u32; 8] = [
    0xFF25_63EB,
    0xFF0E_7490,
    0xFF7C_3AED,
    0xFFDB_2777,
    0xFFEA_580C,
    0xFF16_A34A,
    0xFFCA_8A04,
    0xFF47_5569,
];
