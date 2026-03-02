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

mod info;
mod memory;
mod process;
mod time;
mod misc;

pub use self::info::{cmd_info, cmd_version};
pub use self::memory::{cmd_mem, cmd_df, cmd_free};
pub use self::process::{cmd_ps, cmd_monitor};
pub use self::time::{cmd_uptime, cmd_date};
pub use self::misc::{cmd_cpu, cmd_clear, cmd_hostname, cmd_uname};
