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

use super::{DARK, LIGHT};

/// The chrome's colours under one appearance. Text tokens (`ink`, `ink2`,
/// `muted`) read on every ground the chrome draws (`ground`, `surface`,
/// `sidebar`, `field`), and `on_accent` reads on `accent`.
pub struct Palette {
    pub ground: u32,
    pub surface: u32,
    pub sidebar: u32,
    pub edge: u32,
    pub field: u32,
    pub ink: u32,
    pub ink2: u32,
    pub muted: u32,
    pub accent: u32,
    pub accent_soft: u32,
    pub on_accent: u32,
    pub sky: u32,
    pub teal: u32,
    pub teal_soft: u32,
    pub ok: u32,
    pub err: u32,
    pub disabled: u32,
    pub shadow: u32,
    pub warn: u32,
    pub warn_soft: u32,
}

/* One theme for the whole process: every window and tab paints under it.
 * It starts dark, the default, so a frame drawn before the saved choice is
 * read is already dark. */
static THEME: AtomicU8 = AtomicU8::new(1);

/// The palette the chrome paints with now.
pub fn palette() -> &'static Palette {
    match is_dark() {
        true => &DARK,
        false => &LIGHT,
    }
}

/// Puts the dark palette in force, or the light one.
pub fn set_dark(dark: bool) {
    THEME.store(dark as u8, Ordering::Relaxed);
}

pub fn is_dark() -> bool {
    THEME.load(Ordering::Relaxed) != 0
}
