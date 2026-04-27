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

use super::types::BlockHeader;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize};

pub(super) static mut HEAP_START: usize = 0;
pub(super) static mut HEAP_END: usize = 0;
pub(super) static mut FREE_LIST: *mut BlockHeader = null_mut();
pub(super) static HEAP_INIT: AtomicBool = AtomicBool::new(false);
pub(super) static TOTAL_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
pub(super) static TOTAL_FREED: AtomicUsize = AtomicUsize::new(0);
pub(super) static PEAK_USAGE: AtomicUsize = AtomicUsize::new(0);
