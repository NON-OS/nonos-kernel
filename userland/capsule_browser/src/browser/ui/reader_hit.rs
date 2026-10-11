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

use super::reader_geom::{ReaderGeom, MIN_W};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Close,
    Theme(u8),
    Smaller,
    Larger,
    Width(u8),
    Time,
}

/// The settings control under `(x, y)`; none on a card too narrow to be
/// drawn. The whole reading-time row works the switch.
pub fn hit(g: &ReaderGeom, x: i32, y: i32) -> Option<Control> {
    if g.panel.w < MIN_W {
        return None;
    }
    if g.close.contains(x, y) {
        return Some(Control::Close);
    }
    if let Some(i) = g.swatches.iter().position(|r| r.contains(x, y)) {
        return Some(Control::Theme(i as u8));
    }
    if let Some(i) = g.widths.iter().position(|r| r.contains(x, y)) {
        return Some(Control::Width(i as u8));
    }
    match () {
        _ if g.minus.contains(x, y) => Some(Control::Smaller),
        _ if g.plus.contains(x, y) => Some(Control::Larger),
        _ if g.time.contains(x, y) => Some(Control::Time),
        _ => None,
    }
}
