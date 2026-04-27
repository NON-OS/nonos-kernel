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

use alloc::format;
use alloc::string::String;

pub fn read_pid_io(pid: i32) -> Result<String, i32> {
    let proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    let io = proc.io_stats.lock();
    Ok(format!(
        "rchar: {}\nwchar: {}\nsyscr: {}\nsyscw: {}\nread_bytes: {}\nwrite_bytes: {}\ncancelled_write_bytes: {}\n",
        io.rchar, io.wchar, io.syscr, io.syscw, io.read_bytes, io.write_bytes, io.cancelled_write_bytes
    ))
}

#[derive(Debug, Clone, Copy, Default)]
pub struct IoStats {
    pub rchar: u64,
    pub wchar: u64,
    pub syscr: u64,
    pub syscw: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub cancelled_write_bytes: u64,
}

impl IoStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_read(&mut self, bytes: u64) {
        self.rchar += bytes;
        self.syscr += 1;
        self.read_bytes += bytes;
    }

    pub fn add_write(&mut self, bytes: u64) {
        self.wchar += bytes;
        self.syscw += 1;
        self.write_bytes += bytes;
    }

    pub fn add_cancelled_write(&mut self, bytes: u64) {
        self.cancelled_write_bytes += bytes;
    }
}

pub fn get_io_stats(pid: i32) -> Result<IoStats, i32> {
    let proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    let io = proc.io_stats.lock();
    Ok(IoStats {
        rchar: io.rchar,
        wchar: io.wchar,
        syscr: io.syscr,
        syscw: io.syscw,
        read_bytes: io.read_bytes,
        write_bytes: io.write_bytes,
        cancelled_write_bytes: io.cancelled_write_bytes,
    })
}
