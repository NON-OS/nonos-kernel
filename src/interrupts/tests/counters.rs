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

#[test]
fn test_interrupt_counters_new() {
    let counters = InterruptCounters::new();
    assert_eq!(counters.timer_ticks.load(Ordering::Relaxed), 0);
    assert_eq!(counters.keyboard_presses.load(Ordering::Relaxed), 0);
    assert_eq!(counters.mouse_events.load(Ordering::Relaxed), 0);
    assert_eq!(counters.syscalls.load(Ordering::Relaxed), 0);
    assert_eq!(counters.exceptions.load(Ordering::Relaxed), 0);
    assert_eq!(counters.page_faults.load(Ordering::Relaxed), 0);
}

#[test]
fn test_counters_static_initialization() {
    assert!(COUNTERS.timer_ticks.load(Ordering::Relaxed) < u64::MAX);
    assert!(COUNTERS.keyboard_presses.load(Ordering::Relaxed) < u64::MAX);
    assert!(COUNTERS.mouse_events.load(Ordering::Relaxed) < u64::MAX);
    assert!(COUNTERS.syscalls.load(Ordering::Relaxed) < u64::MAX);
    assert!(COUNTERS.exceptions.load(Ordering::Relaxed) < u64::MAX);
    assert!(COUNTERS.page_faults.load(Ordering::Relaxed) < u64::MAX);
}

#[test]
fn test_increment_timer() {
    let before = COUNTERS.timer_ticks.load(Ordering::Relaxed);
    increment_timer();
    let after = COUNTERS.timer_ticks.load(Ordering::Relaxed);
    assert_eq!(after, before + 1);
}

#[test]
fn test_increment_keyboard() {
    let before = COUNTERS.keyboard_presses.load(Ordering::Relaxed);
    increment_keyboard();
    let after = COUNTERS.keyboard_presses.load(Ordering::Relaxed);
    assert_eq!(after, before + 1);
}

#[test]
fn test_increment_mouse() {
    let before = COUNTERS.mouse_events.load(Ordering::Relaxed);
    increment_mouse();
    let after = COUNTERS.mouse_events.load(Ordering::Relaxed);
    assert_eq!(after, before + 1);
}

#[test]
fn test_increment_syscalls() {
    let before = COUNTERS.syscalls.load(Ordering::Relaxed);
    increment_syscalls();
    let after = COUNTERS.syscalls.load(Ordering::Relaxed);
    assert_eq!(after, before + 1);
}

#[test]
fn test_increment_exceptions() {
    let before = COUNTERS.exceptions.load(Ordering::Relaxed);
    increment_exceptions();
    let after = COUNTERS.exceptions.load(Ordering::Relaxed);
    assert_eq!(after, before + 1);
}

#[test]
fn test_increment_page_faults() {
    let before = COUNTERS.page_faults.load(Ordering::Relaxed);
    increment_page_faults();
    let after = COUNTERS.page_faults.load(Ordering::Relaxed);
    assert_eq!(after, before + 1);
}

#[test]
fn test_get_stats_returns_struct() {
    let stats = get_stats();
    assert!(stats.timer_ticks < u64::MAX);
    assert!(stats.keyboard_presses < u64::MAX);
    assert!(stats.mouse_events < u64::MAX);
    assert!(stats.syscalls < u64::MAX);
    assert!(stats.exceptions < u64::MAX);
    assert!(stats.page_faults < u64::MAX);
}

#[test]
fn test_get_stats_tuple_returns_four_values() {
    let (timer, keyboard, syscalls, exceptions) = get_stats_tuple();
    assert!(timer < u64::MAX);
    assert!(keyboard < u64::MAX);
    assert!(syscalls < u64::MAX);
    assert!(exceptions < u64::MAX);
}

#[test]
fn test_reset_stats() {
    increment_timer();
    increment_keyboard();
    increment_mouse();
    increment_syscalls();
    increment_exceptions();
    increment_page_faults();

    reset_stats();

    let stats = get_stats();
    assert_eq!(stats.timer_ticks, 0);
    assert_eq!(stats.keyboard_presses, 0);
    assert_eq!(stats.mouse_events, 0);
    assert_eq!(stats.syscalls, 0);
    assert_eq!(stats.exceptions, 0);
    assert_eq!(stats.page_faults, 0);
}

#[test]
fn test_interrupt_stats_fields() {
    reset_stats();

    increment_timer();
    increment_timer();
    increment_keyboard();
    increment_syscalls();
    increment_syscalls();
    increment_syscalls();

    let stats = get_stats();
    assert_eq!(stats.timer_ticks, 2);
    assert_eq!(stats.keyboard_presses, 1);
    assert_eq!(stats.syscalls, 3);
}

#[test]
fn test_multiple_increments() {
    reset_stats();

    for _ in 0..100 {
        increment_timer();
    }

    let stats = get_stats();
    assert_eq!(stats.timer_ticks, 100);
}
