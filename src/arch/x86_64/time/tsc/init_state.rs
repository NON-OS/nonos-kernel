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

use super::calibration::{calibrate, calibrate_with_hpet_base};
use super::error::{TscError, TscResult};
use super::features::detect_features;
use super::globals::{FEATURES, INITIALIZED};
use super::per_cpu::init_cpu;
use core::sync::atomic::Ordering;

pub fn init() -> TscResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(TscError::AlreadyInitialized);
    }
    let features = detect_features();
    *FEATURES.write() = features;
    if !features.tsc_available {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(TscError::NotAvailable);
    }
    calibrate()?;
    init_cpu(0)?;
    Ok(())
}

pub fn init_with_hpet(hpet_base: u64) -> TscResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(TscError::AlreadyInitialized);
    }
    let features = detect_features();
    *FEATURES.write() = features;
    if !features.tsc_available {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(TscError::NotAvailable);
    }
    calibrate_with_hpet_base(hpet_base)?;
    init_cpu(0)?;
    Ok(())
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}
