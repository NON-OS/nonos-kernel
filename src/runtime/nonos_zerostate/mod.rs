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

mod registry;
mod capsule_ops;
mod messaging;
mod monitor;

pub use capsule_ops::{register_capsule, start_capsule, stop_capsule, get_capsule_by_name};
pub use messaging::{send_from_capsule, poll_capsule, heartbeat};
pub use monitor::{monitor_once, init_runtime};
