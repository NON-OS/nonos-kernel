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

pub mod input;
pub mod input_actions;
pub mod input_click;
pub mod render;
pub mod render_browser;
pub mod render_browser_help;
pub mod render_elements;
pub mod render_elements_input;
pub mod render_helpers;
pub mod render_tabs;
pub mod render_url_bar;
pub mod render_utils;
pub mod state;
pub mod state_browser;
pub mod state_links;
pub mod state_page;
pub mod state_privacy;
pub mod state_wallet;
pub mod tabs;

pub use input::{handle_click, handle_key, handle_special_key};
pub use render::draw;
pub use state::{get_active_tab, is_input_focused, set_active_tab, EcosystemTab};
