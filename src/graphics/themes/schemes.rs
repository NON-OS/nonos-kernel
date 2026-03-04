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

use super::types::{Theme, ColorScheme};

impl Theme {
    pub fn colors(&self) -> ColorScheme {
        match self {
            Self::NonosDark => ColorScheme {
                bg_primary: 0xFF0D1117,
                bg_secondary: 0xFF161B22,
                bg_tertiary: 0xFF21262D,
                text_primary: 0xFFFFFFFF,
                text_secondary: 0xFF7D8590,
                accent: 0xFF58A6FF,
                success: 0xFF3FB950,
                warning: 0xFFD29922,
                error: 0xFFF85149,
                border: 0xFF30363D,
            },
            Self::GitHubDark => ColorScheme {
                bg_primary: 0xFF0D1117,
                bg_secondary: 0xFF161B22,
                bg_tertiary: 0xFF21262D,
                text_primary: 0xFFC9D1D9,
                text_secondary: 0xFF8B949E,
                accent: 0xFF58A6FF,
                success: 0xFF3FB950,
                warning: 0xFFD29922,
                error: 0xFFF85149,
                border: 0xFF30363D,
            },
            Self::SolarizedDark => ColorScheme {
                bg_primary: 0xFF002B36,
                bg_secondary: 0xFF073642,
                bg_tertiary: 0xFF094656,
                text_primary: 0xFF839496,
                text_secondary: 0xFF586E75,
                accent: 0xFF268BD2,
                success: 0xFF859900,
                warning: 0xFFB58900,
                error: 0xFFDC322F,
                border: 0xFF094656,
            },
            Self::DeepPurple => ColorScheme {
                bg_primary: 0xFF1A0A28,
                bg_secondary: 0xFF261538,
                bg_tertiary: 0xFF3D1F5F,
                text_primary: 0xFFE8E0F0,
                text_secondary: 0xFF9A8AAA,
                accent: 0xFFBB86FC,
                success: 0xFF03DAC5,
                warning: 0xFFFFB74D,
                error: 0xFFCF6679,
                border: 0xFF4A2875,
            },
            Self::OceanBlue => ColorScheme {
                bg_primary: 0xFF0A1A28,
                bg_secondary: 0xFF142838,
                bg_tertiary: 0xFF1E3A5F,
                text_primary: 0xFFE0F0FF,
                text_secondary: 0xFF8AB0CC,
                accent: 0xFF00B4D8,
                success: 0xFF40E0D0,
                warning: 0xFFFFD700,
                error: 0xFFFF6B6B,
                border: 0xFF2A4A6A,
            },
            Self::ForestGreen => ColorScheme {
                bg_primary: 0xFF0A1A0F,
                bg_secondary: 0xFF142A1A,
                bg_tertiary: 0xFF1F3D28,
                text_primary: 0xFFE0F0E8,
                text_secondary: 0xFF8ACC9A,
                accent: 0xFF4CAF50,
                success: 0xFF8BC34A,
                warning: 0xFFCDDC39,
                error: 0xFFFF5722,
                border: 0xFF2A4A32,
            },
        }
    }
}
