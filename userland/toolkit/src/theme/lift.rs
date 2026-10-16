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

//! Lifting a status colour until it reads, keeping its hue.

use super::contrast::at_least;
use super::derive::{mix, opaque};

/// A scale factor of one, in 256ths, so the lift stays in integers.
const ONE: u32 = 256;

/// How far the factor moves on each step, in 256ths.
const SCALE_STEP: u32 = 4;

/// How far the mix moves on each step, once scaling has run out.
const MIX_STEP: u8 = 8;

/// `c` with each channel scaled by `f`/256, rounded and held at 255.
fn scale(c: u32, f: u32) -> u32 {
    let ch = |s: u32| (((c >> s) & 0xFF) * f + ONE / 2) / ONE;
    opaque(ch(16).min(255) << 16 | ch(8).min(255) << 8 | ch(0).min(255))
}

/// The factor at which `seed`'s brightest channel reaches 255, or `ONE` for a
/// black seed, which has nothing to scale.
fn saturates(seed: u32) -> u32 {
    let peak = [16, 8, 0].map(|s| (seed >> s) & 0xFF).into_iter().max().unwrap_or(0);
    (255 * ONE).checked_div(peak).unwrap_or(ONE).max(ONE)
}

/*
 * Scaling every channel by one factor keeps the ratios between them, and so
 * the hue: a warning stays amber as it brightens for a dark ground or darkens
 * for a light one. Only when scaling runs out, at a channel's full 255 or at
 * black, does the colour mix towards white or black, which pales it but still
 * keeps its hue. It never mixes towards the theme's text, which on a cool
 * scheme pulls every status towards the same grey.
 */

/// `seed` brightened (on a dark scheme) or darkened (on a `light` one) by a
/// common factor until it clears `floor` (in tenths) on every one of
/// `grounds`; past that, mixed towards white or black until it does.
pub(super) fn lift(seed: u32, light: bool, grounds: &[u32], floor: u32) -> u32 {
    let reads = |c: u32| grounds.iter().all(|&g| at_least(c, g, floor));
    let (top, mut f) = (saturates(seed), ONE);
    let mut c = scale(seed, f);
    while !reads(c) && (if light { f > 0 } else { f < top }) {
        f = if light { f.saturating_sub(SCALE_STEP) } else { (f + SCALE_STEP).min(top) };
        c = scale(seed, f);
    }
    let toward = if light { opaque(0) } else { opaque(u32::MAX) };
    let mut t = 0u8;
    while !reads(mix(c, toward, t)) && t < u8::MAX {
        t = t.saturating_add(MIX_STEP);
    }
    mix(c, toward, t)
}
