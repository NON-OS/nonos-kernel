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

use alloc::string::String;
use alloc::format;

pub fn resolve_self_link() -> String {
    let pid = crate::process::current_pid();
    format!("{}", pid)
}

pub fn resolve_thread_self_link() -> String {
    let pid = crate::process::current_pid();
    let tid = crate::process::current_tid();
    format!("{}/task/{}", pid, tid)
}

pub fn get_self_target() -> i32 {
    crate::process::current_pid()
}

pub fn is_self_link(path: &str) -> bool {
    path == "/proc/self" || path.starts_with("/proc/self/")
}

pub fn is_thread_self_link(path: &str) -> bool {
    path == "/proc/thread-self" || path.starts_with("/proc/thread-self/")
}

pub fn resolve_proc_path(path: &str) -> String {
    if path.starts_with("/proc/self/") {
        let pid = crate::process::current_pid();
        let rest = &path[11..];
        return format!("/proc/{}/{}", pid, rest);
    }
    if path.starts_with("/proc/thread-self/") {
        let pid = crate::process::current_pid();
        let tid = crate::process::current_tid();
        let rest = &path[18..];
        return format!("/proc/{}/task/{}/{}", pid, tid, rest);
    }
    String::from(path)
}
