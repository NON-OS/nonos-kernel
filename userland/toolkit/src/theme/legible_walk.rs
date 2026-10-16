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

//! Stepping a colour back until it clears the floor against both grounds.

use super::contrast::at_least;
use super::derive::mix;

/*
 * A fixed muting factor cannot work across schemes. Solarized dark puts its own
 * foreground 4.86:1 above its own raised surface, barely over the 4.5:1 floor,
 * while Aurora puts its text at 14.45:1. Muting both by the same third leaves
 * Aurora comfortable and Solarized at 2.81:1, which is below the floor and is
 * exactly the reading a person with low vision cannot follow. A factor safe for
 * Solarized leaves every other scheme's secondary label indistinguishable from
 * its primary one.
 *
 * So the factor is the most muting the scheme can take: it walks back towards
 * the text colour until the result clears the floor against both the ground and
 * the raised surface, because a label does not know which it will be drawn on.
 */
const STEP: u8 = 8;

pub(super) fn walk(text: u32, bg: u32, surface: u32, target: u8, floor: u32) -> u32 {
    walk_on(text, bg, &[bg, surface], target, floor)
}

/// Mixes `text` towards `toward`, stepping back until it clears `floor` on every
/// one of `grounds`. A scheme whose own text fails against its own surface is
/// broken, and unmuted text is the most legible thing available to say so.
pub(super) fn walk_on(text: u32, toward: u32, grounds: &[u32], target: u8, floor: u32) -> u32 {
    let mut t = target;
    loop {
        let candidate = mix(text, toward, t);
        if grounds.iter().all(|&g| at_least(candidate, g, floor)) {
            return candidate;
        }
        if t < STEP {
            return text;
        }
        t -= STEP;
    }
}
