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

//! The arithmetic that turns five theme roles into every colour drawn.

/*
 * Integer only, and rounded rather than truncated. Truncating drifts one level per
 * step, and these compose: a muted label is a mix of a mix. Eight steps of
 * truncation is a visible shift, and it would only show up on some themes.
 */
fn lerp8(a: u8, b: u8, t: u8) -> u8 {
    let a = a as u32;
    let b = b as u32;
    let t = t as u32;
    ((a * (255 - t) + b * t + 127) / 255) as u8
}

/// `a` moved `t`/255 of the way towards `b`, channel by channel. The alpha of `a`
/// is kept: a mix decides a colour, not whether it is see-through.
pub fn mix(a: u32, b: u32, t: u8) -> u32 {
    let ch = |shift: u32| lerp8((a >> shift) as u8, (b >> shift) as u8, t) as u32;
    (a & 0xFF00_0000) | ch(16) << 16 | ch(8) << 8 | ch(0)
}

/// The same colour at a given alpha, for the washes and rings that sit over
/// whatever is behind them.
pub fn with_alpha(colour: u32, alpha: u8) -> u32 {
    (colour & 0x00FF_FFFF) | (alpha as u32) << 24
}

/// Fully opaque, for a colour that has to cover what it is drawn over. A theme's
/// ground arriving with a stray alpha would otherwise let the last frame show
pub fn opaque(colour: u32) -> u32 {
    colour | 0xFF00_0000
}

/// `fill` moved `t`/255 of the way away from `ink`: towards black when the
/// ink is the lighter of the two, towards white when it is the darker. A held
/// control takes this, so pressing it only ever raises its ink's contrast.
pub fn away(fill: u32, ink: u32, t: u8) -> u32 {
    let lighter = super::contrast::luminance(ink) > super::contrast::luminance(fill);
    mix(fill, if lighter { 0xFF00_0000 } else { 0xFFFF_FFFF }, t)
}
