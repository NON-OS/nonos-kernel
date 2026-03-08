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

/* security shell commands - split into focused modules */

mod audit;
mod caps;
mod firewall;
mod integrity;
mod locks;
mod rootkit;
mod sessions;
mod status;

pub use audit::cmd_audit;
pub use caps::cmd_caps;
pub use firewall::cmd_firewall;
pub use integrity::cmd_integrity;
pub use locks::cmd_locks;
pub use rootkit::cmd_rootkit_scan;
pub use sessions::cmd_sessions;
pub use status::cmd_secstatus;
