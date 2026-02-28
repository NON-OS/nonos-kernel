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

use core::sync::atomic::AtomicU64;

pub type SyscallHandler = fn(u64, u64, u64, u64, u64, u64) -> u64;

#[derive(Debug)]
pub struct SyscallInfo {
    pub number: u64,
    pub name: &'static str,
    pub handler: SyscallHandler,
    pub call_count: AtomicU64,
    pub total_time_ns: AtomicU64,
    pub error_count: AtomicU64,
    pub last_called_ns: AtomicU64,
}

impl SyscallInfo {
    pub const fn new(number: u64, name: &'static str, handler: SyscallHandler) -> Self {
        Self {
            number,
            name,
            handler,
            call_count: AtomicU64::new(0),
            total_time_ns: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            last_called_ns: AtomicU64::new(0),
        }
    }
}
