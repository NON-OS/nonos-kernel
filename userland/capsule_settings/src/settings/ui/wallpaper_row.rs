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
use nonos_toolkit::widgets::{Rect, Row, Scrolled, State as Look, Switch};

use crate::settings::state::{cached_value, FieldValue, State};

use super::bytes::as_str;
use super::control_geom::{right_edge, slider_x, switch_rect};
use super::control_str::paint_plain;
use super::metrics::{SWITCH_H, SWITCH_W};

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

/// One wallpaper's row at `at`, in content coordinates, through the toolkit
/// row; the switch or the word standing in for it goes in the control column
/// the row leaves free. `selected` is the keyboard cursor.
pub fn paint(
    fb: &mut PaintBuffer,
    state: &State,
    index: u8,
    scroll: u32,
    at: Rect,
    selected: bool,
) {
    let name = WALLPAPER_LABELS.get(index as usize).copied().unwrap_or(b"");
    let look = Look { focused: selected, hovered: selected, ..Look::default() };
    let room = right_edge(at.x, at.w) - slider_x(at.x, at.w);
    Row::new(as_str(name)).trailing(room).state(look).draw(&mut Scrolled::new(fb, scroll), at);
    let screen_y = at.y as i32 - scroll as i32;
    if desktop(state) == Some(index) {
        paint_plain(fb, "Desktop", right_edge(at.x, at.w), screen_y, at.h);
        return;
    }
    let Some(set) = kept_set(state) else {
        paint_plain(fb, "--", right_edge(at.x, at.w), screen_y, at.h);
        return;
    };
    let (x, y) = switch_rect(at.x, at.w, screen_y, at.h);
    if y >= 0 {
        Switch::new(kept(set, index)).draw(fb, Rect { x, y: y as u32, w: SWITCH_W, h: SWITCH_H });
    }
}
