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

pub mod state;
pub mod tabs;
pub mod render;
pub mod render_helpers;
pub mod render_tabs;
pub mod input;
pub mod input_click;
pub mod input_actions;

pub use state::{EcosystemTab, get_active_tab, set_active_tab, is_input_focused};
pub use render::draw;
pub use input::{handle_click, handle_key, handle_special_key};
