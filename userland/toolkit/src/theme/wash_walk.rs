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

//! Thinning a wash until the text still reads through it.

use super::contrast::at_least;
use super::derive::{mix, opaque, with_alpha};

/*
 * A wash is drawn over a ground to mark a state, and the text on that ground
 * has to read through it. A fixed alpha cannot hold every scheme: Solarized's
 * text clears the body floor on its raised surface by a sliver, and a hover
 * wash of its own text colour takes it under. So each wash starts at its
 * nominal alpha and thins, a step at a time, only as far as the scheme needs.
 * This is the shell's glass walk run the other way: glass grows more opaque to
 * hide what is behind it, a wash grows clearer to show what is under it.
 */

/// How far the alpha falls on each step.
const STEP: u8 = 2;

/// `ground` under `wash`, as a blend paints it over an opaque pixel.
pub(super) fn under(ground: u32, wash: u32) -> u32 {
    opaque(mix(ground, wash, (wash >> 24) as u8))
}

/// `tint` at `alpha`, or as much thinner as it takes for `ink` to clear `floor`
/// (in tenths) through it on every one of `grounds`. It can thin to nothing.
pub(super) fn thin(tint: u32, alpha: u8, ink: u32, grounds: &[u32], floor: u32) -> u32 {
    let mut a = alpha;
    let reads = |a: u8| grounds.iter().all(|&g| at_least(ink, mix(g, tint, a), floor));
    while a > 0 && !reads(a) {
        a = a.saturating_sub(STEP);
    }
    with_alpha(tint, a)
}
