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

//! Status inks that keep their hue and still read on every ground.

use super::super::colour::Opaque;
use super::super::contrast::BODY;
use super::super::legible_walk::walk_on;

/*
 * A status colour carries its meaning in its hue: a reader who has learned that
 * red failed should not have to relearn it when the theme changes. A fixed value
 * cannot also read everywhere. The house red is 4.6:1 on Aurora's ground but
 * 2.5:1 on Dracula's lighter surface, and the dark-tuned green is 1.6:1 on the
 * light theme. So each starts at its fixed value and steps towards the theme's
 * text only as far as the body floor on all four grounds asks.
 */
pub(super) fn status(seed: Opaque, text: u32, grounds: &[u32]) -> Opaque {
    Opaque::new(walk_on(text, seed.argb(), grounds, u8::MAX, BODY))
}
