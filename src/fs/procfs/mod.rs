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
mod inode;
mod mount;
mod root;
mod cpuinfo;
mod meminfo;
mod stat;
mod uptime;
mod version;
mod loadavg;
mod mounts;
mod filesystems;
mod self_link;
pub mod pid;

pub use types::{ProcEntry, ProcEntryType, ProcInode};
pub use inode::{procfs_lookup, procfs_readdir};
pub use mount::{procfs_mount, procfs_unmount, is_procfs_mounted};
pub use root::procfs_root_entries;
pub use cpuinfo::read_cpuinfo;
pub use meminfo::read_meminfo;
pub use stat::read_stat;
pub use uptime::read_uptime;
pub use version::read_version;
pub use loadavg::read_loadavg;
pub use mounts::read_mounts;
pub use filesystems::read_filesystems;
pub use self_link::resolve_self_link;
