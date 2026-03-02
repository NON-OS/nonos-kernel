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


pub const UID_ROOT: u32 = 0;
pub const UID_ANONYMOUS: u32 = 65534;
pub const UID_DEFAULT: u32 = 1000;

pub const GID_ROOT: u32 = 0;
pub const GID_WHEEL: u32 = 10;
pub const GID_USERS: u32 = 100;

pub const MAX_SESSIONS: usize = 64;
pub const HASH_ITERATIONS: usize = 10000;
pub const SALT_SIZE: usize = 16;
pub const TOKEN_SIZE: usize = 32;
pub const SESSION_TIMEOUT_TICKS: u64 = 30 * 60 * 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeLevel {
    Root,
    Admin,
    User,
    Guest,
    Anonymous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Idle,
    Locked,
    Expired,
    Terminated,
}
