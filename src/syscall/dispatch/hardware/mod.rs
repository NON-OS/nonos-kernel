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

mod io;
mod mmio;
mod debug;
mod admin;

pub use io::{handle_io_port_read, handle_io_port_write};
pub use mmio::handle_mmio_map;
pub use debug::{handle_debug_log, handle_debug_trace};
pub use admin::{
    handle_admin_reboot, handle_admin_shutdown, handle_admin_mod_load,
    handle_admin_cap_grant, handle_admin_cap_revoke,
};
