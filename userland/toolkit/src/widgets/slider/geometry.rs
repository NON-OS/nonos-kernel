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

//! Where a slider's track, fill and knob sit, which draw and hit share.

use super::Slider;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{KNOB_R, SLIDER_W, TRACK_H};
use crate::widgets::rect::{centre, share};

/// The placed parts of a slider, in drawing pixels.
pub(super) struct Parts {
    pub(super) body: Rect,
    pub(super) track: Rect,
    pub(super) fill: Rect,
    pub(super) knob: Rect,
    pub(super) dot: (u32, u32),
    pub(super) knob_r: u32,
    pub(super) start: u32,
    pub(super) travel: u32,
}

impl Slider {
    /// `SLIDER_W` wide, and the knob's height with a logical pixel above and below.
    pub fn size(&self) -> (u32, u32) {
        (scale().px(SLIDER_W), scale().px(KNOB_R.saturating_mul(2).saturating_add(2)))
    }

    /// The box across the width of `at`, centred vertically; the track and
    /// its fill up to the knob; and the knob, whose centre travels from
    /// `start` to `start + travel`, a knob radius in from each end of `at`.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let s = scale();
        let body = centre(at, at.w, self.size().1);
        let knob_r = s.px(KNOB_R).min(body.w / 2).min(body.h / 2);
        let start = body.x.saturating_add(knob_r);
        let travel = body.w.saturating_sub(knob_r.saturating_mul(2));
        let cx = start.saturating_add(share(self.value, travel, self.max));
        let side = knob_r.saturating_mul(2);
        let knob = centre(Rect { x: cx.saturating_sub(knob_r), w: side, ..body }, side, side);
        let track = centre(body, body.w, s.px(TRACK_H));
        let fill = Rect { w: cx.saturating_sub(body.x), ..track };
        let dot = (cx, knob.y.saturating_add(knob_r));
        Parts { body, track, fill, knob, dot, knob_r, start, travel }
    }
}
