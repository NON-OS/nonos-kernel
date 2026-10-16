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

//! The scheme table, in the order `THEME_LABELS` lists the names.

use super::{house, published};

/// The five roles every scheme has to fill. Anything the desktop draws resolves
/// to one of these, which is what keeps a new theme from being a half of one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Scheme {
    pub bg: u32,
    pub surface: u32,
    pub accent: u32,
    pub text: u32,
    pub border: u32,
}

/*
 * In the order `THEME_LABELS` lists them, because the stored value is an index
 * into that list. The panel and this table are two halves of one enum, so a theme
 * added to one without the other would paint a window in another theme's colours.
 * `every_theme_name_has_a_scheme` in `theme_proofs` fails if the two lengths part.
 */
pub const SCHEMES: [Scheme; 8] = [
    house::AURORA,
    house::SLATE,
    published::NORD,
    published::DRACULA,
    published::SOLARIZED_DARK,
    house::MONO,
    house::FOREST,
    house::SUNSET,
];

/// The scheme for a stored index. An index past the table falls back to the
/// house theme rather than refusing to paint, because an unpaintable window is
/// worse than one in the house colours.
pub fn scheme(index: u8) -> Scheme {
    match SCHEMES.get(index as usize) {
        Some(found) => *found,
        None => SCHEMES[0],
    }
}
