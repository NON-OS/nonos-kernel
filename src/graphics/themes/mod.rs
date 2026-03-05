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

//! NONOS Theme System
//!
//! Provides UI color schemes and customization options.

use core::sync::atomic::{AtomicU8, Ordering};

/// Currently selected theme
static CURRENT_THEME: AtomicU8 = AtomicU8::new(0);

/// Available color themes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Theme {
    /// Default NONOS dark theme
    NonosDark = 0,
    /// GitHub-inspired dark theme
    GitHubDark = 1,
    /// Solarized dark theme
    SolarizedDark = 2,
    /// Deep purple theme
    DeepPurple = 3,
    /// Ocean blue theme
    OceanBlue = 4,
    /// Forest green theme
    ForestGreen = 5,
}

impl Theme {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::NonosDark,
            1 => Self::GitHubDark,
            2 => Self::SolarizedDark,
            3 => Self::DeepPurple,
            4 => Self::OceanBlue,
            5 => Self::ForestGreen,
            _ => Self::NonosDark,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::NonosDark => "NONOS Dark",
            Self::GitHubDark => "GitHub Dark",
            Self::SolarizedDark => "Solarized Dark",
            Self::DeepPurple => "Deep Purple",
            Self::OceanBlue => "Ocean Blue",
            Self::ForestGreen => "Forest Green",
        }
    }

    pub fn count() -> u8 {
        6
    }

    pub fn next(&self) -> Self {
        let next = (*self as u8 + 1) % Self::count();
        Self::from_u8(next)
    }

    pub fn prev(&self) -> Self {
        let prev = if *self as u8 == 0 {
            Self::count() - 1
        } else {
            *self as u8 - 1
        };
        Self::from_u8(prev)
    }
}

/// Color scheme for a theme
#[derive(Debug, Clone, Copy)]
pub struct ColorScheme {
    /// Primary background color
    pub bg_primary: u32,
    /// Secondary background (panels, headers)
    pub bg_secondary: u32,
    /// Tertiary background (buttons, cards)
    pub bg_tertiary: u32,
    /// Primary text color
    pub text_primary: u32,
    /// Secondary text (dimmed)
    pub text_secondary: u32,
    /// Accent color (highlights, links)
    pub accent: u32,
    /// Success/green color
    pub success: u32,
    /// Warning/yellow color
    pub warning: u32,
    /// Error/red color
    pub error: u32,
    /// Border color
    pub border: u32,
}

impl Theme {
    /// Get the color scheme for this theme
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

/// Get the current theme
pub fn get_theme() -> Theme {
    Theme::from_u8(CURRENT_THEME.load(Ordering::Relaxed))
}

/// Set the current theme
pub fn set_theme(theme: Theme) {
    CURRENT_THEME.store(theme as u8, Ordering::Relaxed);
}

/// Get the current color scheme
pub fn colors() -> ColorScheme {
    get_theme().colors()
}

/// Cycle to next theme
pub fn next_theme() -> Theme {
    let theme = get_theme().next();
    set_theme(theme);
    theme
}

/// Cycle to previous theme
pub fn prev_theme() -> Theme {
    let theme = get_theme().prev();
    set_theme(theme);
    theme
}

// Convenience functions for common colors
pub fn bg_primary() -> u32 { colors().bg_primary }
pub fn bg_secondary() -> u32 { colors().bg_secondary }
pub fn bg_tertiary() -> u32 { colors().bg_tertiary }
pub fn text_primary() -> u32 { colors().text_primary }
pub fn text_secondary() -> u32 { colors().text_secondary }
pub fn accent() -> u32 { colors().accent }
pub fn success() -> u32 { colors().success }
pub fn warning() -> u32 { colors().warning }
pub fn error() -> u32 { colors().error }
pub fn border() -> u32 { colors().border }
