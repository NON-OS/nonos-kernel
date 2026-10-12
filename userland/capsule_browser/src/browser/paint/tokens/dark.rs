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

use super::Palette;

/// The dark chrome, the default: the light one's ink and surfaces inverted, its accents
/// lifted so they still read on the darker grounds. Ink on the accent turns
/// dark, as white on the lighter accent falls short of 4.5:1.
pub static DARK: Palette = Palette {
    ground: 0xFF0F_141C,
    surface: 0xFF16_1C26,
    sidebar: 0xFF12_1822,
    edge: 0xFF27_3142,
    field: 0xFF1E_2633,
    ink: 0xFFE6_EDF5,
    ink2: 0xFFB8_C4D6,
    muted: 0xFF8A_97AB,
    accent: 0xFF5B_8DEF,
    accent_soft: 0xFF23_3554,
    on_accent: 0xFF0B_1220,
    sky: 0xFF1C_2B45,
    teal: 0xFF3F_B8C9,
    teal_soft: 0xFF12_303A,
    ok: 0xFF4A_DE80,
    err: 0xFFF8_7171,
    disabled: 0xFF4E_5A6E,
    shadow: 0x6000_0000,
    warn: 0xFFFB_BF24,
    warn_soft: 0xFF3A_2A0C,
};
