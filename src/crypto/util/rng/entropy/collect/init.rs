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

use super::super::error::EntropyError;
use super::super::hardware::{has_rdrand, has_rdseed};
use super::super::state::{BOOTLOADER_ENTROPY_PROVIDED, HARDWARE_ENTROPY_VERIFIED};
use crate::drivers::tpm;
use crate::drivers::virtio_rng;
use core::sync::atomic::Ordering;

pub fn init_entropy() -> Result<(), EntropyError> {
    if virtio_rng::is_available() {
        HARDWARE_ENTROPY_VERIFIED.store(true, Ordering::SeqCst);
        return Ok(());
    }
    if has_rdrand() || has_rdseed() {
        HARDWARE_ENTROPY_VERIFIED.store(true, Ordering::SeqCst);
        return Ok(());
    }
    if tpm::is_tpm_available() {
        HARDWARE_ENTROPY_VERIFIED.store(true, Ordering::SeqCst);
        return Ok(());
    }
    if BOOTLOADER_ENTROPY_PROVIDED.load(Ordering::SeqCst) {
        return Ok(());
    }
    Err(EntropyError::NoHardwareSource)
}

pub fn mark_bootloader_entropy_provided() {
    BOOTLOADER_ENTROPY_PROVIDED.store(true, Ordering::SeqCst);
}

#[inline]
pub fn has_adequate_entropy() -> bool {
    virtio_rng::is_available()
        || has_rdrand()
        || has_rdseed()
        || tpm::is_tpm_available()
        || BOOTLOADER_ENTROPY_PROVIDED.load(Ordering::Acquire)
}

pub fn verify_entropy_sources() -> Result<(), EntropyError> {
    if virtio_rng::is_available() {
        return Ok(());
    }
    if has_rdrand() || has_rdseed() {
        return Ok(());
    }
    if tpm::is_tpm_available() {
        return Ok(());
    }
    if BOOTLOADER_ENTROPY_PROVIDED.load(Ordering::Acquire) {
        return Ok(());
    }
    Err(EntropyError::NoHardwareSource)
}
