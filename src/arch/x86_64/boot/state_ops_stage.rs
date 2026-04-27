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

use super::error::BootError;
use super::stage::BootStage;
use super::state_globals::*;
use core::sync::atomic::Ordering;

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
pub fn get_stage_tsc(stage: BootStage) -> u64 {
    let idx = stage.as_u8() as usize;
    if idx < STAGE_TSC.len() {
        STAGE_TSC[idx].load(Ordering::Relaxed)
    } else {
        0
    }
}
