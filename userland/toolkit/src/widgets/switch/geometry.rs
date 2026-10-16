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

//! Where a switch's track and knob sit, which draw and hit share.

use super::Switch;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{KNOB_INSET, SWITCH_H, SWITCH_W};
use crate::widgets::rect::centre;

/// The placed parts of a switch, in drawing pixels.
pub(super) struct Parts {
    pub(super) track: Rect,
    pub(super) radius: u32,
    pub(super) knob_x: u32,
    pub(super) knob_y: u32,
    pub(super) knob_r: u32,
}

impl Switch {
    /// The track's size: `SWITCH_W` by `SWITCH_H`.
    pub fn size(&self) -> (u32, u32) {
        let s = scale();
        (s.px(SWITCH_W), s.px(SWITCH_H))
    }

    /// The track, left-aligned and centred vertically in `at`, so a row can
    /// hand it a taller box, and the knob's centre and radius at the end
    /// that `on` picks.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let (w, h) = self.size();
        let track = centre(Rect { w: w.min(at.w), ..at }, w, h);
        let gap = scale().px(KNOB_INSET);
        let knob_r = track.h.min(track.w).saturating_sub(gap.saturating_mul(2)) / 2;
        let reach = gap.saturating_add(knob_r);
        let knob_x = if self.on {
            track.x.saturating_add(track.w.saturating_sub(reach))
        } else {
            track.x.saturating_add(reach)
        };
        Parts {
            track,
            radius: track.h / 2,
            knob_x,
            knob_y: track.y.saturating_add(track.h / 2),
            knob_r,
        }
    }
}
