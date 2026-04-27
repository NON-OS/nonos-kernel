// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::graphics::window::apps::{
    draw_about, draw_agents, draw_browser, draw_developer, draw_ecosystem, draw_marketplace,
    draw_process_manager, draw_wallet,
};
use crate::graphics::window::calculator::draw_calculator;
use crate::graphics::window::file_manager::draw_file_manager;
use crate::graphics::window::settings::draw_settings;
use crate::graphics::window::state::WindowType;
use crate::graphics::window::terminal::draw_terminal;
use crate::graphics::window::text_editor::draw_text_editor;

pub(super) fn draw_window_content(x: u32, y: u32, w: u32, h: u32, wtype: WindowType) {
    match wtype {
        WindowType::Calculator => draw_calculator(x, y, w, h),
        WindowType::FileManager => draw_file_manager(x, y, w, h),
        WindowType::TextEditor => draw_text_editor(x, y, w, h),
        WindowType::Settings => draw_settings(x, y, w, h),
        WindowType::About => draw_about(x, y, w, h),
        WindowType::ProcessManager => draw_process_manager(x, y, w, h),
        WindowType::Browser => draw_browser(x, y, w, h),
        WindowType::Terminal => draw_terminal(x, y, w, h),
        WindowType::Wallet => draw_wallet(x, y, w, h),
        WindowType::Ecosystem => draw_ecosystem(x, y, w, h),
        WindowType::Marketplace => draw_marketplace(x, y, w, h),
        WindowType::Developer => draw_developer(x, y, w, h),
        WindowType::Agents => draw_agents(x, y, w, h),
        WindowType::None => {}
    }
}
