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

use core::sync::atomic::{AtomicU64, Ordering};

pub struct InterruptCounters {
    pub timer_ticks: AtomicU64,
    pub keyboard_presses: AtomicU64,
    pub mouse_events: AtomicU64,
    pub syscalls: AtomicU64,
    pub exceptions: AtomicU64,
    pub page_faults: AtomicU64,
}

impl InterruptCounters {
    pub const fn new() -> Self {
        Self {
            timer_ticks: AtomicU64::new(0),
            keyboard_presses: AtomicU64::new(0),
            mouse_events: AtomicU64::new(0),
            syscalls: AtomicU64::new(0),
            exceptions: AtomicU64::new(0),
            page_faults: AtomicU64::new(0),
        }
    }
}

pub static COUNTERS: InterruptCounters = InterruptCounters::new();

#[inline]
pub fn increment_timer() {
    COUNTERS.timer_ticks.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_keyboard() {
    COUNTERS.keyboard_presses.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_mouse() {
    COUNTERS.mouse_events.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_syscalls() {
    COUNTERS.syscalls.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_exceptions() {
    COUNTERS.exceptions.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_page_faults() {
    COUNTERS.page_faults.fetch_add(1, Ordering::Relaxed);
}
