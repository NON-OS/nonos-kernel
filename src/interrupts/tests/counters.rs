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

use core::sync::atomic::Ordering;

use crate::interrupts::*;
use crate::test::framework::TestResult;

pub(crate) fn test_interrupt_counters_new() -> TestResult {
    let counters = InterruptCounters::new();
    if counters.timer_ticks.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if counters.keyboard_presses.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if counters.mouse_events.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if counters.syscalls.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if counters.exceptions.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if counters.page_faults.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_counters_static_initialization() -> TestResult {
    if !(COUNTERS.timer_ticks.load(Ordering::Relaxed) < u64::MAX) {
        return TestResult::Fail;
    }
    if !(COUNTERS.keyboard_presses.load(Ordering::Relaxed) < u64::MAX) {
        return TestResult::Fail;
    }
    if !(COUNTERS.mouse_events.load(Ordering::Relaxed) < u64::MAX) {
        return TestResult::Fail;
    }
    if !(COUNTERS.syscalls.load(Ordering::Relaxed) < u64::MAX) {
        return TestResult::Fail;
    }
    if !(COUNTERS.exceptions.load(Ordering::Relaxed) < u64::MAX) {
        return TestResult::Fail;
    }
    if !(COUNTERS.page_faults.load(Ordering::Relaxed) < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_increment_timer() -> TestResult {
    let before = COUNTERS.timer_ticks.load(Ordering::Relaxed);
    increment_timer();
    let after = COUNTERS.timer_ticks.load(Ordering::Relaxed);
    if after != before + 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_increment_keyboard() -> TestResult {
    let before = COUNTERS.keyboard_presses.load(Ordering::Relaxed);
    increment_keyboard();
    let after = COUNTERS.keyboard_presses.load(Ordering::Relaxed);
    if after != before + 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_increment_mouse() -> TestResult {
    let before = COUNTERS.mouse_events.load(Ordering::Relaxed);
    increment_mouse();
    let after = COUNTERS.mouse_events.load(Ordering::Relaxed);
    if after != before + 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_increment_syscalls() -> TestResult {
    let before = COUNTERS.syscalls.load(Ordering::Relaxed);
    increment_syscalls();
    let after = COUNTERS.syscalls.load(Ordering::Relaxed);
    if after != before + 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_increment_exceptions() -> TestResult {
    let before = COUNTERS.exceptions.load(Ordering::Relaxed);
    increment_exceptions();
    let after = COUNTERS.exceptions.load(Ordering::Relaxed);
    if after != before + 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_increment_page_faults() -> TestResult {
    let before = COUNTERS.page_faults.load(Ordering::Relaxed);
    increment_page_faults();
    let after = COUNTERS.page_faults.load(Ordering::Relaxed);
    if after != before + 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_stats_returns_struct() -> TestResult {
    let stats = get_stats();
    if !(stats.timer_ticks < u64::MAX) {
        return TestResult::Fail;
    }
    if !(stats.keyboard_presses < u64::MAX) {
        return TestResult::Fail;
    }
    if !(stats.mouse_events < u64::MAX) {
        return TestResult::Fail;
    }
    if !(stats.syscalls < u64::MAX) {
        return TestResult::Fail;
    }
    if !(stats.exceptions < u64::MAX) {
        return TestResult::Fail;
    }
    if !(stats.page_faults < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_stats_tuple_returns_four_values() -> TestResult {
    let (timer, keyboard, syscalls, exceptions) = get_stats_tuple();
    if !(timer < u64::MAX) {
        return TestResult::Fail;
    }
    if !(keyboard < u64::MAX) {
        return TestResult::Fail;
    }
    if !(syscalls < u64::MAX) {
        return TestResult::Fail;
    }
    if !(exceptions < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reset_stats() -> TestResult {
    increment_timer();
    increment_keyboard();
    increment_mouse();
    increment_syscalls();
    increment_exceptions();
    increment_page_faults();

    reset_stats();

    let stats = get_stats();
    if stats.timer_ticks != 0 {
        return TestResult::Fail;
    }
    if stats.keyboard_presses != 0 {
        return TestResult::Fail;
    }
    if stats.mouse_events != 0 {
        return TestResult::Fail;
    }
    if stats.syscalls != 0 {
        return TestResult::Fail;
    }
    if stats.exceptions != 0 {
        return TestResult::Fail;
    }
    if stats.page_faults != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interrupt_stats_fields() -> TestResult {
    reset_stats();

    increment_timer();
    increment_timer();
    increment_keyboard();
    increment_syscalls();
    increment_syscalls();
    increment_syscalls();

    let stats = get_stats();
    if stats.timer_ticks != 2 {
        return TestResult::Fail;
    }
    if stats.keyboard_presses != 1 {
        return TestResult::Fail;
    }
    if stats.syscalls != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_increments() -> TestResult {
    reset_stats();

    for _ in 0..100 {
        increment_timer();
    }

    let stats = get_stats();
    if stats.timer_ticks != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
