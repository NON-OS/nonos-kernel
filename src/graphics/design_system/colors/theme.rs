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

use super::{dark, light};
use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Theme {
    Dark = 0,
    Light = 1,
    System = 2,
}

static CURRENT_THEME: AtomicU8 = AtomicU8::new(0);

pub fn get_theme() -> Theme {
    match CURRENT_THEME.load(Ordering::Relaxed) {
        1 => Theme::Light,
        2 => Theme::System,
        _ => Theme::Dark,
    }
}

pub fn set_theme(theme: Theme) {
    CURRENT_THEME.store(theme as u8, Ordering::Relaxed);
}

pub fn is_dark_mode() -> bool {
    matches!(get_theme(), Theme::Dark | Theme::System)
}

#[inline]
pub fn bg_app() -> u32 {
    if is_dark_mode() {
        dark::BG_APP
    } else {
        light::BG_APP
    }
}

#[inline]
pub fn bg_surface() -> u32 {
    if is_dark_mode() {
        dark::BG_SURFACE
    } else {
        light::BG_SURFACE
    }
}

#[inline]
pub fn bg_elevated() -> u32 {
    if is_dark_mode() {
        dark::BG_ELEVATED
    } else {
        light::BG_ELEVATED
    }
}

#[inline]
pub fn bg_input() -> u32 {
    if is_dark_mode() {
        dark::BG_INPUT
    } else {
        light::BG_INPUT
    }
}

#[inline]
pub fn bg_hover() -> u32 {
    if is_dark_mode() {
        dark::BG_HOVER
    } else {
        light::BG_HOVER
    }
}

#[inline]
pub fn text_primary() -> u32 {
    if is_dark_mode() {
        dark::TEXT_PRIMARY
    } else {
        light::TEXT_PRIMARY
    }
}

#[inline]
pub fn text_secondary() -> u32 {
    if is_dark_mode() {
        dark::TEXT_SECONDARY
    } else {
        light::TEXT_SECONDARY
    }
}

#[inline]
pub fn border_default() -> u32 {
    if is_dark_mode() {
        dark::BORDER_DEFAULT
    } else {
        light::BORDER_DEFAULT
    }
}

#[inline]
pub fn border_focus() -> u32 {
    if is_dark_mode() {
        dark::BORDER_FOCUS
    } else {
        light::BORDER_FOCUS
    }
}
