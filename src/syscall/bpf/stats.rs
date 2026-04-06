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

static PROGRAMS_LOADED: AtomicU64 = AtomicU64::new(0);
static MAPS_CREATED: AtomicU64 = AtomicU64::new(0);
static VERIFIER_PASSES: AtomicU64 = AtomicU64::new(0);
static VERIFIER_FAILURES: AtomicU64 = AtomicU64::new(0);

pub fn record_program_loaded() {
    PROGRAMS_LOADED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_map_created() {
    MAPS_CREATED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_verifier_pass() {
    VERIFIER_PASSES.fetch_add(1, Ordering::Relaxed);
}

pub fn record_verifier_failure() {
    VERIFIER_FAILURES.fetch_add(1, Ordering::Relaxed);
}

pub fn get_programs_loaded() -> u64 {
    PROGRAMS_LOADED.load(Ordering::Relaxed)
}

pub fn get_maps_created() -> u64 {
    MAPS_CREATED.load(Ordering::Relaxed)
}

pub fn get_verifier_passes() -> u64 {
    VERIFIER_PASSES.load(Ordering::Relaxed)
}

pub fn get_verifier_failures() -> u64 {
    VERIFIER_FAILURES.load(Ordering::Relaxed)
}

pub struct BpfStats {
    pub programs_loaded: u64,
    pub maps_created: u64,
    pub verifier_passes: u64,
    pub verifier_failures: u64,
}

pub fn get_stats() -> BpfStats {
    BpfStats {
        programs_loaded: PROGRAMS_LOADED.load(Ordering::Relaxed),
        maps_created: MAPS_CREATED.load(Ordering::Relaxed),
        verifier_passes: VERIFIER_PASSES.load(Ordering::Relaxed),
        verifier_failures: VERIFIER_FAILURES.load(Ordering::Relaxed),
    }
}

pub fn reset_stats() {
    PROGRAMS_LOADED.store(0, Ordering::Relaxed);
    MAPS_CREATED.store(0, Ordering::Relaxed);
    VERIFIER_PASSES.store(0, Ordering::Relaxed);
    VERIFIER_FAILURES.store(0, Ordering::Relaxed);
}
