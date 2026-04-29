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

pub mod accessibility;
pub mod appearance;
pub mod display;
pub mod input;
pub mod kernel;
pub mod keyboard;
pub mod lock;
pub mod mouse;
pub mod network;
pub mod power;
pub mod privacy;
pub mod render;
pub mod sound;
pub mod state;
pub mod system;

pub(super) use input::handle_click as handle_settings_click;
pub use power::process_power_actions;
pub(super) use render::draw as draw_settings;
pub use state::reset_all as reset_render_state;
pub use system::take_background_changed;
