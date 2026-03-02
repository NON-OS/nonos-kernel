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
use crate::process::core as nonos_core;

#[inline]
pub fn spawn(name: &str) -> Result<nonos_core::Pid, &'static str> {
    nonos_core::create_process(name, nonos_core::ProcessState::Ready, nonos_core::Priority::Normal)
}

#[inline]
pub fn kill(pid: nonos_core::Pid, code: i32) -> Result<(), &'static str> {
    let Some(p) = nonos_core::get_process_table().find_by_pid(pid) else {
        return Err("not found");
    };
    p.terminate(code);
    Ok(())
}

#[inline]
pub fn set_name(pid: nonos_core::Pid, name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty name");
    }
    let Some(p) = nonos_core::get_process_table().find_by_pid(pid) else {
        return Err("not found");
    };
    *p.name.lock() = String::from(name);
    Ok(())
}
