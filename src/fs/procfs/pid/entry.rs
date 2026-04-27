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

use crate::fs::procfs::types::ProcEntry;
use alloc::vec::Vec;

pub fn pid_entries(pid: i32) -> Vec<ProcEntry> {
    let base = (pid as u64) << 20;
    alloc::vec![
        ProcEntry::file("status", base | 1),
        ProcEntry::file("stat", base | 2),
        ProcEntry::file("cmdline", base | 3),
        ProcEntry::file("maps", base | 4),
        ProcEntry::directory("fd", base | 5),
        ProcEntry::file("environ", base | 6),
        ProcEntry::symlink("exe", base | 7),
        ProcEntry::symlink("cwd", base | 8),
        ProcEntry::symlink("root", base | 9),
        ProcEntry::file("comm", base | 10),
        ProcEntry::file("io", base | 11),
        ProcEntry::file("statm", base | 12),
        ProcEntry::file("limits", base | 13),
        ProcEntry::file("wchan", base | 14),
        ProcEntry::file("stack", base | 15),
        ProcEntry::file("smaps", base | 16),
        ProcEntry::file("smaps_rollup", base | 17),
        ProcEntry::file("oom_score", base | 18),
        ProcEntry::file("oom_score_adj", base | 19),
        ProcEntry::file("oom_adj", base | 20),
        ProcEntry::file("loginuid", base | 21),
        ProcEntry::file("sessionid", base | 22),
        ProcEntry::file("auxv", base | 23),
        ProcEntry::file("personality", base | 24),
        ProcEntry::directory("task", base | 100),
        ProcEntry::directory("net", base | 101),
        ProcEntry::directory("ns", base | 102),
        ProcEntry::directory("attr", base | 103),
    ]
}

pub fn pid_entry_inode(pid: i32, name: &str) -> Option<u64> {
    pid_entries(pid).iter().find(|e| e.name == name).map(|e| e.inode)
}
