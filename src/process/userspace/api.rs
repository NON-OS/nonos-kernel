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

use core::sync::atomic::{AtomicBool, Ordering};
use super::transitions::{enable_smep, enable_smap};

static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    crate::log::info!("[USERSPACE] Initializing user-space execution engine...");

    let cpuid = core::arch::x86_64::__cpuid_count(7, 0);

    if cpuid.ebx & (1 << 7) != 0 {
        enable_smep();
    } else {
        crate::log::log_warning!("[USERSPACE] SMEP not supported by CPU");
    }

    if cpuid.ebx & (1 << 20) != 0 {
        enable_smap();
    } else {
        crate::log::log_warning!("[USERSPACE] SMAP not supported by CPU");
    }

    crate::log::info!("[USERSPACE] User-space execution engine initialized");

    Ok(())
}
