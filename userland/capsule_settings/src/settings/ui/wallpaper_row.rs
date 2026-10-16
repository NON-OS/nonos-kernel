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

//! One wallpaper of the collection: its name, and a switch saying whether
//! it is kept. The desktop's wallpaper is always kept and says so instead.

use nonos_app_skeleton::PaintBuffer;
use nonos_policy_proto::wallpaper_labels::WALLPAPER_LABELS;
use nonos_policy_proto::wallpapers_kept::kept;
use nonos_policy_proto::Field;
use nonos_toolkit::widgets::{Rect, Switch};

use crate::settings::state::{cached_value, FieldValue, State};

use super::bytes::as_str;
use super::control_geom::{right_edge, switch_rect};
use super::control_str::paint_plain;
use super::metrics::{SWITCH_H, SWITCH_W};
use super::row_label;

/// The kept set as the panel last read it: every wallpaper until it has.
/// The kept set as the store gave it; None when it was not read. Every
/// switch showed On then, and a toggle wrote that guess over the real set.
pub fn kept_set(state: &State) -> Option<u64> {
    match cached_value(state, Field::WallpapersKept) {
        FieldValue::U64(set) => Some(set),
        _ => None,
    }
}

/// The desktop's wallpaper as the panel last read it.
pub fn desktop(state: &State) -> Option<u8> {
    match cached_value(state, Field::Wallpaper) {
        FieldValue::U8(v) => Some(v),
        _ => None,
    }
}

/// One wallpaper's row. Its focus ring, when the row is selected, is painted
/// first by the caller (pane.rs) with row_focus.
pub fn paint(
    fb: &mut PaintBuffer,
    state: &State,
    index: u8,
    card_x: u32,
    card_w: u32,
    screen_y: i32,
    row_h: u32,
) {
    let name = WALLPAPER_LABELS.get(index as usize).copied().unwrap_or(b"");
    row_label::paint(fb, card_x, screen_y, row_h, as_str(name), None);
    if desktop(state) == Some(index) {
        paint_plain(fb, "Desktop", right_edge(card_x, card_w), screen_y, row_h);
        return;
    }
    let Some(set) = kept_set(state) else {
        paint_plain(fb, "--", right_edge(card_x, card_w), screen_y, row_h);
        return;
    };
    let (x, y) = switch_rect(card_x, card_w, screen_y, row_h);
    if y >= 0 {
        Switch::new(kept(set, index)).draw(fb, Rect { x, y: y as u32, w: SWITCH_W, h: SWITCH_H });
    }
}
