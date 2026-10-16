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

//! The grounds a widget can draw ink on: each flat ground, and each of them
//! under the selected wash, under the hover wash and under both.

use super::super::contrast::BODY;
use super::super::derive::mix;
use super::super::wash_walk::{thin, under};

const BLACK: u32 = 0xFF00_0000;

/// The selected wash's alpha where the scheme can take it.
const ACCENT_WASH: u8 = 0x20;

/// The hover wash's alpha where the scheme can take it.
const HOVER_WASH: u8 = 0x14;

/// The four flat grounds: `bg`, `sunken` (`bg` a little darker), `surface`
/// and `raised` (`surface` a little towards the accent).
pub(super) fn flat_grounds(bg: u32, surface: u32, accent: u32) -> [u32; 4] {
    [bg, mix(bg, BLACK, 12), surface, mix(surface, accent, 11)]
}

/// The two washes, thinned for the scheme, and the sixteen grounds they make
/// of the four flat ones: flat, selected, hovered, then selected and hovered.
pub(super) struct StateGrounds {
    pub accent_wash: u32,
    pub hover_wash: u32,
    pub all: [u32; 16],
}

/// The state grounds of `flat`, with each wash thinned until `text` reads at
/// the body floor through it. The selected wash is drawn first, so the hover
/// wash is thinned over the selected grounds too.
pub(super) fn state_grounds(flat: [u32; 4], accent: u32, text: u32) -> StateGrounds {
    let accent_wash = thin(accent, ACCENT_WASH, text, &flat, BODY);
    let mut all = [0u32; 16];
    all[..4].copy_from_slice(&flat);
    for i in 0..4 {
        all[4 + i] = under(flat[i], accent_wash);
    }
    let hover_wash = thin(text, HOVER_WASH, text, &all[..8], BODY);
    for i in 0..8 {
        all[8 + i] = under(all[i], hover_wash);
    }
    StateGrounds { accent_wash, hover_wash, all }
}
