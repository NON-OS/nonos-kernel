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

use super::oom_killer::trigger_oom_killer;
use crate::mem::allocator::{get_free_pages, get_total_pages};
use crate::mem::swap::trigger_swap_out;
use crate::process::ProcessManager;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

static PRESSURE_LEVEL: AtomicU8 = AtomicU8::new(0);
static LAST_CHECK: AtomicU64 = AtomicU64::new(0);

const PRESSURE_LOW: u8 = 1;
const PRESSURE_MEDIUM: u8 = 2;
const PRESSURE_HIGH: u8 = 3;
const PRESSURE_CRITICAL: u8 = 4;

pub fn check_memory_pressure() {
    let current_time = crate::time::current_time_ms();
    let last_check = LAST_CHECK.load(Ordering::Acquire);

    if current_time - last_check < 1000 {
        return;
    }

    LAST_CHECK.store(current_time, Ordering::Release);

    let free_pages = get_free_pages();
    let total_pages = get_total_pages();
    let free_percentage = (free_pages * 100) / total_pages;

    let new_level = match free_percentage {
        0..=5 => PRESSURE_CRITICAL,
        6..=15 => PRESSURE_HIGH,
        16..=25 => PRESSURE_MEDIUM,
        26..=40 => PRESSURE_LOW,
        _ => 0,
    };

    let old_level = PRESSURE_LEVEL.swap(new_level, Ordering::AcqRel);

    if new_level > old_level {
        handle_pressure_increase(new_level);
    }
}

fn handle_pressure_increase(level: u8) {
    match level {
        PRESSURE_LOW => {
            ProcessManager::send_signal_to_all(10);
        }
        PRESSURE_MEDIUM => {
            trigger_swap_out(1024);
            ProcessManager::throttle_allocations();
        }
        PRESSURE_HIGH => {
            trigger_swap_out(4096);
            ProcessManager::suspend_non_critical();
        }
        PRESSURE_CRITICAL => {
            trigger_oom_killer(0);
        }
        _ => {}
    }
}

pub fn get_current_pressure() -> u8 {
    PRESSURE_LEVEL.load(Ordering::Acquire)
}

pub fn is_memory_available(pages_needed: usize) -> bool {
    let free_pages = get_free_pages();
    let pressure = get_current_pressure();

    match pressure {
        PRESSURE_CRITICAL => false,
        PRESSURE_HIGH => free_pages > pages_needed * 4,
        PRESSURE_MEDIUM => free_pages > pages_needed * 2,
        _ => free_pages > pages_needed,
    }
}
