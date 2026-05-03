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

mod controller;
mod cpu;
mod io;
mod memory;
mod pids;
mod types;

pub use controller::{
    attach_process, create_cgroup, delete_cgroup, detach_process, get_cgroup_for_pid,
};
pub use cpu::{check_cpu_limit, get_cpu_usage, set_cpu_limit, CpuLimit};
pub use io::{check_io_limit, get_io_stats, set_io_limit, IoLimit};
pub use memory::{check_memory_limit, get_memory_usage, set_memory_limit, MemoryLimit};
pub use pids::{check_pids_limit, get_pids_count, set_pids_limit, PidsLimit};
pub use types::{CgroupController, CgroupError, CgroupId, CgroupStats};
