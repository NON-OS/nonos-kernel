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

extern crate alloc;

use super::types::ProcEntry;
use alloc::vec::Vec;

pub fn procfs_root_entries() -> Vec<ProcEntry> {
    alloc::vec![
        ProcEntry::file("cpuinfo", 10),
        ProcEntry::file("meminfo", 11),
        ProcEntry::file("stat", 12),
        ProcEntry::file("uptime", 13),
        ProcEntry::file("version", 14),
        ProcEntry::file("loadavg", 15),
        ProcEntry::file("mounts", 16),
        ProcEntry::file("filesystems", 17),
        ProcEntry::file("cmdline", 18),
        ProcEntry::file("interrupts", 19),
        ProcEntry::file("devices", 20),
        ProcEntry::file("partitions", 21),
        ProcEntry::file("diskstats", 22),
        ProcEntry::file("vmstat", 23),
        ProcEntry::file("swaps", 24),
        ProcEntry::file("modules", 25),
        ProcEntry::directory("sys", 100),
        ProcEntry::directory("net", 101),
        ProcEntry::directory("bus", 102),
        ProcEntry::directory("driver", 103),
        ProcEntry::directory("fs", 104),
        ProcEntry::directory("irq", 105),
    ]
}

pub fn root_entry_by_name(name: &str) -> Option<ProcEntry> {
    procfs_root_entries().into_iter().find(|e| e.name == name)
}

pub fn root_entry_by_inode(ino: u64) -> Option<ProcEntry> {
    procfs_root_entries().into_iter().find(|e| e.inode == ino)
}
