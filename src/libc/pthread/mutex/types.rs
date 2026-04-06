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

use core::sync::atomic::AtomicU32;

pub const PTHREAD_MUTEX_NORMAL: i32 = 0;
pub const PTHREAD_MUTEX_RECURSIVE: i32 = 1;
pub const PTHREAD_MUTEX_ERRORCHECK: i32 = 2;

#[repr(C)]
pub struct PthreadMutex {
    pub lock: AtomicU32,
    pub kind: i32,
    pub owner: u64,
    pub count: u32,
}

#[repr(C)]
pub struct PthreadMutexattr {
    pub kind: i32,
}
