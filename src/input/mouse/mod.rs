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

pub mod driver;
pub mod interrupt;
pub mod poll;
pub mod ps2;
pub mod state;

pub use driver::has_scroll_wheel;
pub use driver::init;
pub use interrupt::handle_interrupt;
pub use poll::poll;
pub use state::is_available;
pub use state::{buttons, middle_pressed, scroll_delta, take_scroll_delta};
pub(crate) use state::{left_pressed, position, right_pressed, set_screen_bounds};
