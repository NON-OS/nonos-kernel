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

use core::sync::atomic::{AtomicU32, Ordering};

static TESTS_RUN: AtomicU32 = AtomicU32::new(0);
static TESTS_PASSED: AtomicU32 = AtomicU32::new(0);
static TESTS_FAILED: AtomicU32 = AtomicU32::new(0);
static TESTS_SKIPPED: AtomicU32 = AtomicU32::new(0);

pub fn reset_counters() {
    TESTS_RUN.store(0, Ordering::SeqCst);
    TESTS_PASSED.store(0, Ordering::SeqCst);
    TESTS_FAILED.store(0, Ordering::SeqCst);
    TESTS_SKIPPED.store(0, Ordering::SeqCst);
}

pub fn get_stats() -> (u32, u32, u32, u32) {
    (
        TESTS_RUN.load(Ordering::SeqCst),
        TESTS_PASSED.load(Ordering::SeqCst),
        TESTS_FAILED.load(Ordering::SeqCst),
        TESTS_SKIPPED.load(Ordering::SeqCst),
    )
}

pub(crate) fn record_pass() {
    TESTS_RUN.fetch_add(1, Ordering::SeqCst);
    TESTS_PASSED.fetch_add(1, Ordering::SeqCst);
}

pub(crate) fn record_fail() {
    TESTS_RUN.fetch_add(1, Ordering::SeqCst);
    TESTS_FAILED.fetch_add(1, Ordering::SeqCst);
}

pub(crate) fn record_skip() {
    TESTS_RUN.fetch_add(1, Ordering::SeqCst);
    TESTS_SKIPPED.fetch_add(1, Ordering::SeqCst);
}
