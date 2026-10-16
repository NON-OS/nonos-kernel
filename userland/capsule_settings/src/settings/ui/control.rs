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

use nonos_app_skeleton::PaintBuffer;
use nonos_policy_proto::wallpaper_labels::WALLPAPER_LABELS;
use nonos_policy_proto::{enum_table, kind_of, Field, KIND_BOOL, KIND_I8, KIND_STR, KIND_U64, KIND_U8};
use nonos_toolkit::widgets::{Rect, Slider, Switch};

use crate::settings::schema::read_only;
use crate::settings::state::{cached_value, FieldValue, State};

use super::control_geom::{right_edge, slider_x, switch_rect};
use super::control_str::{paint_bool_text, paint_choice, paint_number, paint_plain, paint_string};
use super::control_value::percent;
use super::metrics::{SLIDER_W, SWITCH_H, SWITCH_W};

pub fn paint(
    fb: &mut PaintBuffer,
    state: &State,
    field: Field,
    card_x: u32,
    card_w: u32,
    screen_y: i32,
    row_h: u32,
) {
    let value = cached_value(state, field);
    let cy = screen_y + (row_h / 2) as i32;
    let right = right_edge(card_x, card_w);
    match kind_of(field) {
        KIND_BOOL if read_only(field) => paint_bool_text(fb, value, right, screen_y, row_h),
        KIND_BOOL => {
            let (x, y) = switch_rect(card_x, card_w, screen_y, row_h);
            if y >= 0 {
                let at = Rect { x, y: y as u32, w: SWITCH_W, h: SWITCH_H };
                Switch::new(matches!(value, FieldValue::Bool(true))).draw(fb, at);
            }
        }
        KIND_U8 if enum_table(field).is_some() => {
            paint_choice(fb, field, value, right, screen_y, row_h)
        }
        KIND_U8 => {
            let sx = slider_x(card_x, card_w);
            let slider = Slider::new(percent(field, value), 100);
            let h = slider.size().1;
            let top = cy - (h / 2) as i32;
            if top >= 0 {
                slider.draw(fb, Rect { x: sx, y: top as u32, w: SLIDER_W, h });
            }
            paint_number(fb, value, sx.saturating_sub(12), screen_y, row_h);
        }
        KIND_I8 => paint_number(fb, value, right, screen_y, row_h),
        KIND_STR => paint_string(fb, state, field, &value, right, screen_y, row_h),
        KIND_U64 => {
            let said = match value {
                FieldValue::U64(set) => {
                    alloc::format!("{} of {}", set.count_ones(), WALLPAPER_LABELS.len())
                }
                _ => alloc::string::String::from("--"),
            };
            paint_plain(fb, &said, right, screen_y, row_h);
        }
        _ => {}
    }
}
