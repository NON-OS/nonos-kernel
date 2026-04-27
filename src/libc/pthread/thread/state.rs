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

use super::constants::MAX_THREADS;
use super::types::ThreadControlBlock;
use core::sync::atomic::AtomicU64;
use spin::Mutex;

pub static THREAD_TABLE: Mutex<[Option<ThreadControlBlock>; MAX_THREADS]> =
    Mutex::new([const { None }; MAX_THREADS]);
pub static NEXT_TID: AtomicU64 = AtomicU64::new(1);
pub static CURRENT_THREAD: AtomicU64 = AtomicU64::new(0);
