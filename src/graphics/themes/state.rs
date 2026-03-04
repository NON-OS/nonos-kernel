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

use core::sync::atomic::{AtomicU8, Ordering};
use super::types::{Theme, ColorScheme};

static CURRENT_THEME: AtomicU8 = AtomicU8::new(0);

pub fn get_theme() -> Theme {
    Theme::from_u8(CURRENT_THEME.load(Ordering::Relaxed))
}

pub fn set_theme(theme: Theme) {
    CURRENT_THEME.store(theme as u8, Ordering::Relaxed);
}

pub fn colors() -> ColorScheme {
    get_theme().colors()
}

pub fn next_theme() -> Theme {
    let theme = get_theme().next();
    set_theme(theme);
    theme
}

pub fn prev_theme() -> Theme {
    let theme = get_theme().prev();
    set_theme(theme);
    theme
}

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
