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

use super::state_globals::*;
use core::sync::atomic::Ordering;

#[inline]
pub fn set_complete(complete: bool) {
    BOOT_COMPLETE.store(complete, Ordering::SeqCst);
}

#[inline]
pub fn is_complete() -> bool {
    BOOT_COMPLETE.load(Ordering::Acquire)
}

#[inline]
pub fn set_boot_tsc(tsc: u64) {
    BOOT_TSC.store(tsc, Ordering::SeqCst);
}

#[inline]
pub fn get_boot_tsc() -> u64 {
    BOOT_TSC.load(Ordering::Acquire)
}

#[inline]
pub fn increment_exception_count() {
    EXCEPTION_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn get_exception_count() -> u64 {
    EXCEPTION_COUNT.load(Ordering::Acquire)
}
