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

pub const IPC_CREAT: i32 = 0o1000;
pub const IPC_EXCL: i32 = 0o2000;
pub const IPC_NOWAIT: i32 = 0o4000;
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_PRIVATE: u64 = 0;

pub const SHM_RDONLY: i32 = 0o10000;
pub const SHM_RND: i32 = 0o20000;
pub const SHM_REMAP: i32 = 0o40000;
pub const SHM_EXEC: i32 = 0o100000;
pub const SHM_LOCK: i32 = 11;
pub const SHM_UNLOCK: i32 = 12;
pub const SHM_STAT: i32 = 13;
pub const SHM_INFO: i32 = 14;

pub const GETVAL: i32 = 12;
pub const SETVAL: i32 = 16;
pub const GETPID: i32 = 11;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;
pub const GETALL: i32 = 13;
pub const SETALL: i32 = 17;
pub const SEM_STAT: i32 = 18;
pub const SEM_INFO: i32 = 19;

pub const MSG_STAT: i32 = 11;
pub const MSG_INFO: i32 = 12;
pub const MSG_NOERROR: i32 = 0o10000;
pub const MSG_EXCEPT: i32 = 0o20000;
pub const MSG_COPY: i32 = 0o40000;

pub const SHMMAX: usize = 256 * 1024 * 1024;
pub const SHMMIN: usize = 1;
pub const SHMMNI: usize = 4096;

pub const SEMMNI: usize = 128;
pub const SEMMSL: usize = 250;
pub const SEMOPM: usize = 32;

pub const MSGMNI: i32 = 32000;
pub const MSGMAX: usize = 8192;
pub const MSGMNB: usize = 16384;
