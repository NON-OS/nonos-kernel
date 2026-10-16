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

//! A see-through ground that keeps its text readable whatever shows through it.

use nonos_toolkit::theme::contrast::at_least;
use nonos_toolkit::theme::derive::{mix, with_alpha};
use nonos_toolkit::theme::Opaque;

/// The darkest and the lightest that can show through: every channel empty, and
/// every channel full.
pub(super) const BEHIND: [u32; 2] = [Opaque::new(0).argb(), Opaque::new(u32::MAX).argb()];

/// How far the alpha rises on each step.
const STEP: u8 = 8;

/*
 * A fixed alpha cannot hold every scheme. Aurora's text reads at 10.9:1 on its
 * panel with white showing through at the shell's alpha, while Solarized's
 * text, at only 4.86:1 on its own surface when solid, falls to 3.6:1. So the
 * ground starts at the alpha the shell is drawn with and grows more opaque,
 * a step at a time, only as far as the scheme needs.
 */

/// `ground` at `alpha`, or as much more opaque as it takes for every one of
/// `inks` to clear its floor (in tenths) with black or white behind it.
pub(super) fn glass(ground: Opaque, alpha: u8, inks: &[(Opaque, u32)]) -> u32 {
    let mut a = alpha;
    while a < u8::MAX && !inks.iter().all(|&(ink, floor)| reads(ink, ground, a, floor)) {
        a = a.saturating_add(STEP);
    }
    with_alpha(ground.argb(), a)
}

/// Whether `ink` clears `floor` on `ground` at `alpha` over both extremes.
fn reads(ink: Opaque, ground: Opaque, alpha: u8, floor: u32) -> bool {
    BEHIND.iter().all(|&behind| at_least(ink.argb(), mix(behind, ground.argb(), alpha), floor))
}
