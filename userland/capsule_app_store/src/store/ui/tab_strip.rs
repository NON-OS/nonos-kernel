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

//! The source tabs as one toolkit strip across the set. The frame draws it
//! and a click and the hover ask its own hit test, so a tab's highlight and
//! the area that answers a click are the one rectangle the strip lays out.

use nonos_toolkit::widgets::{Rect, Surface, Tabs};

use crate::store::tab::{Tab, TABS};

use super::bytes::as_str;
use super::metrics::{HEAD_H, PAD_TOP, PAD_X, TAB_H};

/// The tabs' labels, in `TABS` order.
fn labels() -> [&'static str; TABS.len()] {
    TABS.map(|t| as_str(t.label()))
}

/// The band below the head the strip lays its tabs in, across the window
/// inside its side gutters.
pub fn band(fb_w: u32) -> Rect {
    Rect { x: PAD_X, y: PAD_TOP + HEAD_H, w: fb_w.saturating_sub(PAD_X * 2), h: TAB_H }
}

/// Draws the strip with the tab `on` chosen, or none, and the tab at
/// `hovered` washed.
pub fn draw(fb: &mut impl Surface, fb_w: u32, on: Option<Tab>, hovered: Option<usize>) {
    let labels = labels();
    let selected = TABS.iter().position(|t| Some(*t) == on).unwrap_or(TABS.len());
    Tabs::new(&labels, selected).hovered(hovered).draw(fb, band(fb_w));
}

/// The index of the tab whose highlight holds the point, if any.
pub fn tab_at(fb_w: u32, x: i32, y: i32) -> Option<usize> {
    Tabs::new(&labels(), 0).hit(band(fb_w), x, y)
}
