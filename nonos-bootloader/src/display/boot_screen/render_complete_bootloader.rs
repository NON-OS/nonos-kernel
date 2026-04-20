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

use crate::display::gop::get_dimensions;
use crate::display::font::draw_string;
use crate::display::constants::COLOR_TEXT_WHITE;

use super::{
    draw_gradient_background::draw_gradient_background,
    draw_particle_effects::draw_particle_effects,
    draw_animated_logo::draw_animated_logo,
    draw_progress_bar::draw_progress_bar,
    draw_stage_indicators::draw_stage_indicators,
    draw_boot_messages::draw_boot_messages,
    draw_spinning_indicator::draw_spinning_indicator,
    draw_status_items::draw_status_items,
    draw_system_info::draw_system_info,
    get_stage_name::get_stage_name,
    update_animation_timer::update_animation_timer,
};

static mut CURRENT_BOOT_STAGE: u8 = 0;

pub fn render_complete_bootloader() {
    let (width, height) = get_dimensions();

    update_animation_timer();

    draw_gradient_background(width, height);
    draw_particle_effects(width, height);
    draw_animated_logo(width / 2, height / 4);

    let progress_y = height * 2 / 3;
    let progress_width = width - 200;
    let progress_x = 100;

    let stage_name = get_stage_name(unsafe { CURRENT_BOOT_STAGE });
    draw_string(progress_x, progress_y - 50, stage_name.as_bytes(), COLOR_TEXT_WHITE);

    draw_progress_bar(progress_x, progress_y, progress_width, 24);
    draw_spinning_indicator(progress_x + progress_width + 40, progress_y + 12);

    draw_stage_indicators(progress_x + progress_width + 80, progress_y - 40);
    draw_status_items(100, progress_y + 60);
    draw_boot_messages(100, height - 200);
    draw_system_info(width, height);
}

pub fn set_boot_stage(stage: u8) {
    unsafe { CURRENT_BOOT_STAGE = stage; }
}