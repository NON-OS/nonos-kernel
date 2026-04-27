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

use super::render_text::draw_text_area;
use super::render_ui::{draw_file_picker, draw_line_numbers, draw_status_bar, draw_toolbar};
use super::state::*;
use super::tabs_render::{draw_tabs, TAB_BAR_HEIGHT};
use super::tabs_state::tabs_enabled;

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    if picker_is_active() {
        draw_file_picker(x, y, w, h);
        return;
    }
    let tab_offset = if tabs_enabled() {
        draw_tabs(x, y, w);
        TAB_BAR_HEIGHT
    } else {
        0
    };
    let content_y = y + tab_offset;
    let content_h = h - tab_offset;
    draw_toolbar(x, content_y, w);
    draw_line_numbers(
        x,
        content_y + TOOLBAR_HEIGHT,
        content_h - TOOLBAR_HEIGHT - STATUS_BAR_HEIGHT,
    );
    draw_text_area(x, content_y, w, content_h);
    draw_status_bar(x, content_y, w, content_h);
}
