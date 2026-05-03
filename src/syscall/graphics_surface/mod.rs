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

mod create;
mod cursor_present;
mod destroy;
mod display_dimensions;
mod display_list;
mod map;
mod pixel_format;
mod present;
mod present_rect;
mod reclaim;
mod registry;
mod va_alloc;

pub use create::sys_surface_create;
pub use cursor_present::sys_cursor_present;
pub use destroy::sys_surface_destroy;
pub use display_dimensions::sys_display_dimensions;
pub use display_list::sys_display_list;
pub use map::sys_surface_map;
pub use present::sys_surface_present_full;
pub use present_rect::sys_surface_present_rect;
pub use reclaim::release_for;
