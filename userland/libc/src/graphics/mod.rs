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

mod cursor_present;
mod display_dimensions;
mod display_list;
mod surface_create;
mod surface_destroy;
mod surface_map;
mod surface_present;
mod surface_present_rect;

pub use cursor_present::nonos_cursor_present;
pub use display_dimensions::nonos_display_dimensions;
pub use display_list::{nonos_display_list, NonosDisplayInfo};
pub use surface_create::{nonos_surface_create, NONOS_PIXEL_FMT_ARGB8888};
pub use surface_destroy::nonos_surface_destroy;
pub use surface_map::nonos_surface_map;
pub use surface_present::nonos_surface_present_full;
pub use surface_present_rect::nonos_surface_present_rect;
