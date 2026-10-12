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

//! Colours that stay the same under either appearance.

/// Ink on the window frame, which the titlebar tab strip sits on.
pub const ON_FRAME: u32 = nonos_toolkit::decorations::TITLE_TEXT;

/// The reader's themes, Light, Sepia and Dark: ground, ink, and muted ink.
pub const READER_THEMES: [[u32; 3]; 3] = [
    [0xFFFF_FFFF, 0xFF1F_2937, 0xFF6B_7280],
    [0xFFF6_EED9, 0xFF43_3422, 0xFF8A_7558],
    [0xFF16_1A22, 0xFFE5_E7EB, 0xFF9C_A3AF],
];

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

/// The letter on a tile, and the name on a group's chip in its colour.
pub const TILE_INK: u32 = 0xFFFF_FFFF;
