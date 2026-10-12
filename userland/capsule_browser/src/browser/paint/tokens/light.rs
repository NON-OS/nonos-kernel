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

/// The light chrome.
pub static LIGHT: Palette = Palette {
    ground: 0xFFF4_F7FC,
    surface: 0xFFFF_FFFF,
    sidebar: 0xFFE8_EEF8,
    edge: 0xFFD9_E2EF,
    field: 0xFFEE_F2F8,
    ink: 0xFF13_213A,
    ink2: 0xFF33_4460,
    muted: 0xFF5B_6B85,
    accent: 0xFF25_63EB,
    accent_soft: 0xFFDB_E7FF,
    on_accent: 0xFFFF_FFFF,
    sky: 0xFFA9_CBFA,
    teal: 0xFF0E_7490,
    teal_soft: 0xFFDD_F6F8,
    ok: 0xFF16_A34A,
    err: 0xFFDC_2626,
    disabled: 0xFFA9_B4C6,
    shadow: 0x3010_1828,
    warn: 0xFFB4_5309,
    warn_soft: 0xFFFE_F3C7,
};
