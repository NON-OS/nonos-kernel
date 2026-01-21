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

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use super::error::BootError;
use super::stage::BootStage;
use super::types::BootStats;

static BOOT_STAGE: AtomicU8 = AtomicU8::new(0);
static BOOT_ERROR: AtomicU8 = AtomicU8::new(0);
static BOOT_COMPLETE: AtomicBool = AtomicBool::new(false);
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);
static EXCEPTION_COUNT: AtomicU64 = AtomicU64::new(0);

static STAGE_TSC: [AtomicU64; BootStage::COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

#[inline]
pub fn set_stage(stage: BootStage, tsc: u64) {
    BOOT_STAGE.store(stage.as_u8(), Ordering::SeqCst);
    let idx = stage.as_u8() as usize;
    if idx < STAGE_TSC.len() {
        STAGE_TSC[idx].store(tsc, Ordering::Relaxed);
    }
}

#[inline]
pub fn get_stage() -> BootStage {
    BootStage::from_u8(BOOT_STAGE.load(Ordering::Acquire))
}

#[inline]
pub fn set_error(error: BootError) {
    BOOT_ERROR.store(error as u8, Ordering::SeqCst);
}

#[inline]
pub fn get_error() -> BootError {
    BootError::from_u8(BOOT_ERROR.load(Ordering::Acquire))
}

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

#[inline]
pub fn get_stage_tsc(stage: BootStage) -> u64 {
    let idx = stage.as_u8() as usize;
    if idx < STAGE_TSC.len() {
        STAGE_TSC[idx].load(Ordering::Relaxed)
    } else {
        0
    }
}

pub fn get_stats() -> BootStats {
    let mut stage_tsc = [0u64; BootStage::COUNT];
    for i in 0..BootStage::COUNT {
        stage_tsc[i] = STAGE_TSC[i].load(Ordering::Relaxed);
    }

    BootStats {
        stage: BOOT_STAGE.load(Ordering::Relaxed),
        error: BOOT_ERROR.load(Ordering::Relaxed),
        complete: BOOT_COMPLETE.load(Ordering::Relaxed),
        boot_tsc: BOOT_TSC.load(Ordering::Relaxed),
        complete_tsc: stage_tsc[BootStage::Complete.as_u8() as usize],
        exceptions: EXCEPTION_COUNT.load(Ordering::Relaxed),
        stage_tsc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_operations() {
        set_stage(BootStage::Entry, 1000);
        assert_eq!(get_stage(), BootStage::Entry);
        assert_eq!(get_stage_tsc(BootStage::Entry), 1000);
    }

    #[test]
    fn test_error_operations() {
        set_error(BootError::NoSse);
        assert_eq!(get_error(), BootError::NoSse);
    }

    #[test]
    fn test_complete_flag() {
        set_complete(false);
        assert!(!is_complete());
        set_complete(true);
        assert!(is_complete());
    }

    #[test]
    fn test_exception_count() {
        let initial = get_exception_count();
        increment_exception_count();
        assert_eq!(get_exception_count(), initial + 1);
    }
}
