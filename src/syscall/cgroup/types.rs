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

pub type CgroupId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupError {
    NotFound,
    AlreadyExists,
    LimitExceeded,
    InvalidLimit,
    PermissionDenied,
    NotEmpty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupController { Memory, Cpu, Pids, Io, All }

#[derive(Debug, Default)]
pub struct CgroupStats {
    pub memory_current: AtomicU64,
    pub memory_peak: AtomicU64,
    pub cpu_usage_usec: AtomicU64,
    pub pids_current: AtomicU64,
    pub io_read_bytes: AtomicU64,
    pub io_write_bytes: AtomicU64,
    pub oom_kills: AtomicU64,
    pub throttled_usec: AtomicU64,
}
