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

use super::plan::{target, MAX_RASTER_PX};
use super::resident::{charge, refund};
use super::shrink::Shrink;
use super::store::Store;
use super::store_entry::Status;

/// Drawn as the content of an <img> or other replaced box.
pub(crate) const IMG_BOX: u8 = 1;
/// Drawn as a background layer.
#[cfg(not(feature = "harness"))]
pub(crate) const BG_BOX: u8 = 2;

impl Store {
    /// Record one way the page draws `url` (IMG_BOX or BG_BOX).
    pub(crate) fn note_drawn_as(&mut self, url: &str, how: u8) {
        if let Some(e) = self.entries.get_mut(url) {
            e.drawn_as |= how;
        }
    }

    /// Mark `url` as drawn on or near the screen, as the device's requeue
    /// pass does after each layout; the host harness has no such pass.
    #[cfg(feature = "harness")]
    pub fn note_near(&mut self, url: &str) {
        self.entry(url).near = true;
    }

    /// Whether `url` is drawn only as box content, so vector art may be
    /// rasterized at the box's own shape.
    pub(crate) fn only_in_img_box(&self, url: &str) -> bool {
        self.entries.get(url).is_some_and(|e| e.drawn_as == IMG_BOX)
    }

    /// Grow the noted display size; the largest referencing box wins so
    /// the raster is sharp everywhere it appears. A raster already decoded
    /// larger than that box needs (one that landed while its box still
    /// waited on the natural size, so no hint was known then) is
    /// box-filtered down to it in place, and the difference goes back to
    /// the budget.
    pub(crate) fn note_hint(&mut self, url: &str, w: u32, h: u32) {
        let Some(e) = self.entries.get_mut(url) else { return };
        e.hint = (e.hint.0.max(w), e.hint.1.max(h));
        let Status::Ready(d) = &e.status else { return };
        let want = target((d.w, d.h), e.hint, MAX_RASTER_PX);
        if want.0 >= d.w && want.1 >= d.h {
            return;
        }
        /* The larger raster stays when the smaller one cannot be allocated. */
        let Some(mut s) = Shrink::new((d.w, d.h), want) else { return };
        for (y, row) in d.px.chunks(d.w.max(1) as usize).enumerate() {
            s.row(y, row);
        }
        let (before, small) = (d.px.len() * 4, s.finish());
        self.bytes = self.bytes.saturating_sub(before) + small.px.len() * 4;
        refund(before);
        charge(small.px.len() * 4);
        e.status = Status::Ready(small);
    }
}
