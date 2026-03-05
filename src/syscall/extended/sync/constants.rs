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

pub(super) const FUTEX_WAIT: i32 = 0;
pub(super) const FUTEX_WAKE: i32 = 1;
pub(super) const FUTEX_FD: i32 = 2;
pub(super) const FUTEX_REQUEUE: i32 = 3;
pub(super) const FUTEX_CMP_REQUEUE: i32 = 4;
pub(super) const FUTEX_WAKE_OP: i32 = 5;
pub(super) const FUTEX_LOCK_PI: i32 = 6;
pub(super) const FUTEX_UNLOCK_PI: i32 = 7;
pub(super) const FUTEX_TRYLOCK_PI: i32 = 8;
pub(super) const FUTEX_WAIT_BITSET: i32 = 9;
pub(super) const FUTEX_WAKE_BITSET: i32 = 10;
pub(super) const FUTEX_WAIT_REQUEUE_PI: i32 = 11;
pub(super) const FUTEX_CMP_REQUEUE_PI: i32 = 12;
pub(super) const FUTEX_LOCK_PI2: i32 = 13;

pub(super) const FUTEX_OP_SET: u32 = 0;
pub(super) const FUTEX_OP_ADD: u32 = 1;
pub(super) const FUTEX_OP_OR: u32 = 2;
pub(super) const FUTEX_OP_ANDN: u32 = 3;
pub(super) const FUTEX_OP_XOR: u32 = 4;

pub(super) const FUTEX_OP_CMP_EQ: u32 = 0;
pub(super) const FUTEX_OP_CMP_NE: u32 = 1;
pub(super) const FUTEX_OP_CMP_LT: u32 = 2;
pub(super) const FUTEX_OP_CMP_LE: u32 = 3;
pub(super) const FUTEX_OP_CMP_GT: u32 = 4;
pub(super) const FUTEX_OP_CMP_GE: u32 = 5;

pub(super) const FUTEX_TID_MASK: u32 = 0x3FFFFFFF;
pub(super) const FUTEX_WAITERS: u32 = 0x80000000;
pub(super) const FUTEX_OWNER_DIED: u32 = 0x40000000;

pub(super) const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFFFFFF;
