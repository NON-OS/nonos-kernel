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

mod buttons;
pub mod history;
pub mod memory;
mod numbers;
pub mod operations;
mod render;
mod render_history;
mod render_scientific;
pub mod scientific;
mod state;

pub use history::{is_visible as is_history_visible, toggle_visible as toggle_history};
pub use memory::{memory_add, memory_clear, memory_recall, memory_store, memory_subtract};
pub(crate) use render::draw_calculator;
pub use scientific::{is_scientific_mode, toggle_scientific_mode};
pub(crate) use state::*;
