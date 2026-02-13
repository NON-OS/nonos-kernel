// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicU8, Ordering};
use uefi::prelude::*;
use uefi::table::boot::BootServices;

use crate::log::types::LogLevel;

/// Global pointer to UEFI Boot Services for logging
static BOOT_SERVICES: AtomicPtr<BootServices> = AtomicPtr::new(core::ptr::null_mut());

/// Global pointer to UEFI System Table for logging
static SYSTEM_TABLE: AtomicPtr<SystemTable<Boot>> = AtomicPtr::new(core::ptr::null_mut());

static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

static MIN_LOG_LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);

static BOOT_START_TICK: AtomicU64 = AtomicU64::new(0);

static LOG_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn init_global_state(st: &mut SystemTable<Boot>) {
    let bs_ptr = st.boot_services() as *const BootServices as *mut BootServices;
    let st_ptr = st as *mut SystemTable<Boot>;

    BOOT_SERVICES.store(bs_ptr, Ordering::Release);
    SYSTEM_TABLE.store(st_ptr, Ordering::Release);
    LOGGER_INITIALIZED.store(true, Ordering::Release);
    // Initialize boot tick
    let tick = get_current_tick_internal(bs_ptr);
    BOOT_START_TICK.store(tick, Ordering::Release);
}

/// Shutdown the global logger (before ExitBootServices)
pub fn shutdown_global_state() {
    LOGGER_INITIALIZED.store(false, Ordering::Release);
    BOOT_SERVICES.store(core::ptr::null_mut(), Ordering::Release);
    SYSTEM_TABLE.store(core::ptr::null_mut(), Ordering::Release);
}

pub fn is_initialized() -> bool {
    LOGGER_INITIALIZED.load(Ordering::Acquire)
}

pub fn get_boot_services() -> *mut BootServices {
    BOOT_SERVICES.load(Ordering::Acquire)
}

pub fn get_system_table() -> *mut SystemTable<Boot> {
    SYSTEM_TABLE.load(Ordering::Acquire)
}

pub fn set_min_level(level: LogLevel) {
    MIN_LOG_LEVEL.store(level as u8, Ordering::Release);
}

pub fn get_min_level() -> LogLevel {
    LogLevel::from_u8(MIN_LOG_LEVEL.load(Ordering::Acquire)).unwrap_or(LogLevel::Info)
}

pub fn should_log(level: LogLevel) -> bool {
    if !is_initialized() {
        return false;
    }
    level.should_log(get_min_level())
}

pub fn get_boot_tick() -> u64 {
    let bs_ptr = BOOT_SERVICES.load(Ordering::Acquire);
    if bs_ptr.is_null() {
        return 0;
    }

    let current = get_current_tick_internal(bs_ptr);
    let start = BOOT_START_TICK.load(Ordering::Acquire);
    current.saturating_sub(start)
}

fn get_current_tick_internal(bs_ptr: *mut BootServices) -> u64 {
    if bs_ptr.is_null() {
        return 0;
    }
    // ** Dev: I need to switch to a UEFI timer or TSC next, since now is a STS 
    LOG_COUNT.load(Ordering::Acquire)
}

pub fn increment_log_count() -> u64 {
    LOG_COUNT.fetch_add(1, Ordering::AcqRel)
}

pub fn get_log_count() -> u64 {
    LOG_COUNT.load(Ordering::Acquire)
}

/// Reset log count (for testing)
pub fn reset_log_count() {
    LOG_COUNT.store(0, Ordering::Release);
}
