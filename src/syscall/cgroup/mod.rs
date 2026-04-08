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

mod types;
mod controller;
mod memory;
mod cpu;
mod pids;
mod io;

pub use types::{CgroupId, CgroupError, CgroupController, CgroupStats};
pub use controller::{create_cgroup, delete_cgroup, attach_process, detach_process, get_cgroup_for_pid};
pub use memory::{MemoryLimit, set_memory_limit, get_memory_usage, check_memory_limit};
pub use cpu::{CpuLimit, set_cpu_limit, get_cpu_usage, check_cpu_limit};
pub use pids::{PidsLimit, set_pids_limit, get_pids_count, check_pids_limit};
pub use io::{IoLimit, set_io_limit, get_io_stats, check_io_limit};
