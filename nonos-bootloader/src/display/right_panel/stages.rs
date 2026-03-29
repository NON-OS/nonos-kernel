// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::display::font::draw_string;
use crate::display::gop::fill_rect;
use super::frame::RightPanelLayout;

const COLOR_ACTIVE: u32 = 0x66FFFF;
const COLOR_DONE: u32 = 0x66FFAA;
const COLOR_PENDING: u32 = 0x404050;
const COLOR_BAR_BG: u32 = 0x1A2020;
const COLOR_BAR_FG: u32 = 0x66FFFF;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StageState {
    Pending,
    Active,
    Done,
    Failed,
}

pub struct StageInfo<'a> {
    pub name: &'a [u8],
    pub state: StageState,
}

pub fn render_stage(layout: &RightPanelLayout, y_offset: u32, stage: &StageInfo) {
    let y = layout.content_y + y_offset;
    let (prefix, color) = match stage.state {
        StageState::Pending => (b"[ ]" as &[u8], COLOR_PENDING),
        StageState::Active => (b"[>]" as &[u8], COLOR_ACTIVE),
        StageState::Done => (b"[+]" as &[u8], COLOR_DONE),
        StageState::Failed => (b"[X]" as &[u8], 0xFF6666),
    };

    draw_string(layout.content_x, y, prefix, color);
    draw_string(layout.content_x + 32, y, stage.name, color);
}

pub fn render_progress_bar(layout: &RightPanelLayout, progress: u8) {
    let bar_y = layout.y + layout.height - 40;
    let bar_w = layout.width - 32;
    let filled_w = ((bar_w as u32) * (progress as u32)) / 100;

    fill_rect(layout.x + 16, bar_y, bar_w, 8, COLOR_BAR_BG);
    if filled_w > 0 {
        fill_rect(layout.x + 16, bar_y, filled_w, 8, COLOR_BAR_FG);
    }
}
