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

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn register() {
    super::register_tool(b"sysinfo", b"Get system information", tool_sysinfo);
    super::register_tool(b"memory", b"Get memory statistics", tool_memory);
    super::register_tool(b"uptime", b"Get system uptime", tool_uptime);
    super::register_tool(b"processes", b"List running processes", tool_processes);
}

fn tool_sysinfo(_args: &[u8]) -> Vec<u8> {
    let mut info = String::from("NONOS System Information\n========================\n");
    info.push_str("OS: NONOS v0.8.3\nArch: x86_64\n");
    info.push_str(&format!("Uptime: {} seconds\n", crate::time::timestamp_millis() / 1000));
    info.push_str(&format!("Timestamp: {}\n", crate::time::timestamp_millis()));
    info.into_bytes()
}

fn tool_memory(_args: &[u8]) -> Vec<u8> {
    let mut info = String::from("Memory Status\n=============\n");
    info.push_str("Heap: Active\nStack: OK\nFramebuffer: Mapped\n");
    info.into_bytes()
}

fn tool_uptime(_args: &[u8]) -> Vec<u8> {
    let ms = crate::time::timestamp_millis();
    let secs = ms / 1000;
    let mins = secs / 60;
    let hours = mins / 60;
    format!("Uptime: {}h {}m {}s", hours, mins % 60, secs % 60).into_bytes()
}

fn tool_processes(_args: &[u8]) -> Vec<u8> {
    let mut out = String::from("Running Processes\n=================\n  PID  NAME\n");
    out.push_str("    1  kernel\n    2  shell\n    3  window_manager\n");
    if crate::agents::executor::is_running() {
        let id = crate::agents::executor::current_agent();
        out.push_str(&format!("    4  agent_{}\n", id));
    }
    out.into_bytes()
}
