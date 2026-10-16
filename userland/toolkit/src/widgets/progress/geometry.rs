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

//! Where a progress bar's track and fill sit.

use super::Progress;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::PROGRESS_H;
use crate::widgets::rect::{centre, share};

/// The placed parts of a progress bar, in drawing pixels.
pub(super) struct Parts {
    pub(super) track: Rect,
    pub(super) fill: Rect,
    pub(super) radius: u32,
}

impl Progress {
    /// No width of its own, since a bar fills the width it is given, by
    /// `PROGRESS_H`.
    pub fn size(&self) -> (u32, u32) {
        (0, scale().px(PROGRESS_H))
    }

    /// The track across the width of `at`, `PROGRESS_H` tall and centred
    /// vertically, with a radius of half its height; the fill is its left
    /// `done / total` share, rounded to the nearest pixel.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let track = centre(at, at.w, self.size().1);
        let fill = Rect { w: share(self.done, track.w, self.total), ..track };
        Parts { track, fill, radius: track.h / 2 }
    }
}
