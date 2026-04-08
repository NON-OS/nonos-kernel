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
use super::frequency_cpuid::{detect_tsc_frequency_cpuid_15h, detect_frequency_cpuid_16h};
use super::frequency_pit::calibrate_tsc_with_pit;

static TSC_FREQUENCY: AtomicU64 = AtomicU64::new(0);
static CORE_FREQUENCY: AtomicU64 = AtomicU64::new(0);

pub fn tsc_frequency() -> u64 {
    let freq = TSC_FREQUENCY.load(Ordering::Relaxed);
    if freq > 0 { return freq; }
    if let Some(f) = detect_tsc_frequency_cpuid_15h() { TSC_FREQUENCY.store(f, Ordering::Relaxed); return f; }
    if let Some(f) = detect_frequency_cpuid_16h() { TSC_FREQUENCY.store(f, Ordering::Relaxed); return f; }
    let f = calibrate_tsc_with_pit();
    TSC_FREQUENCY.store(f, Ordering::Relaxed);
    f
}

pub fn core_frequency() -> u64 {
    let freq = CORE_FREQUENCY.load(Ordering::Relaxed);
    if freq > 0 { return freq; }
    if let Some(f) = detect_frequency_cpuid_16h() { CORE_FREQUENCY.store(f, Ordering::Relaxed); return f; }
    let f = tsc_frequency();
    CORE_FREQUENCY.store(f, Ordering::Relaxed);
    f
}

pub fn get_tsc_frequency() -> u64 {
    TSC_FREQUENCY.load(Ordering::Relaxed)
}

pub fn get_core_frequency() -> u64 {
    CORE_FREQUENCY.load(Ordering::Relaxed)
}
