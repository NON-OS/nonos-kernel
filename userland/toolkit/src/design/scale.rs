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

//! The display scale: how many drawing pixels one logical pixel takes, counted
//! in quarters, so 4 is 1x, 5 is 1.25x, 6 is 1.5x and 8 is 2x. The rounding
//! matches the desktop shell's, so the toolkit and the shell size alike.

use core::sync::atomic::{AtomicU32, Ordering};

/// The smallest scale, 1x.
const MIN_QUARTERS: u32 = 4;
/// The largest scale, 4x.
const MAX_QUARTERS: u32 = 16;

/// The current scale, in quarters. Nothing sets it yet, so it stays at 1x.
static QUARTERS: AtomicU32 = AtomicU32::new(MIN_QUARTERS);

/// A display scale, in quarters of a pixel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scale(u32);

impl Scale {
    /// The raw scale, in quarters.
    pub const fn quarters(self) -> u32 {
        self.0
    }

    /// `logical` pixels on the canvas, rounded to the nearest pixel.
    pub const fn px(self, logical: u32) -> u32 {
        logical.saturating_mul(self.0).saturating_add(2) / 4
    }

    /// A hairline, in whole pixels: never thinner than one.
    pub const fn hair(self) -> u32 {
        let whole = self.0 / 4;
        if whole == 0 {
            1
        } else {
            whole
        }
    }

    /// A logical font size in drawing pixels. The readable floor is applied
    /// later by the text code, not here.
    pub fn font(self, px: f32) -> f32 {
        px * self.0 as f32 / 4.0
    }
}

/// The current display scale.
pub fn scale() -> Scale {
    Scale(QUARTERS.load(Ordering::Relaxed))
}

/// Set the display scale, in quarters. The value is clamped to 4..=16 (1x to
/// 4x), so a bad value can neither shrink the interface nor blow it up.
pub fn set_scale(quarters: u32) {
    QUARTERS.store(quarters.clamp(MIN_QUARTERS, MAX_QUARTERS), Ordering::Relaxed);
}
