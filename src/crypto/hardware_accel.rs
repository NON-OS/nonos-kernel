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

static HARDWARE_ACCEL_ENABLED: AtomicBool = AtomicBool::new(true);
static AES_NI_AVAILABLE: AtomicBool = AtomicBool::new(false);
static SHA_NI_AVAILABLE: AtomicBool = AtomicBool::new(false);

pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        let features = crate::arch::x86_64::cpu::features::CpuFeatures::detect();
        AES_NI_AVAILABLE.store(features.aes_ni, Ordering::SeqCst);
        SHA_NI_AVAILABLE.store(features.sha, Ordering::SeqCst);
    }
}

pub fn set_enabled(enabled: bool) {
    HARDWARE_ACCEL_ENABLED.store(enabled, Ordering::SeqCst);
}
pub fn is_enabled() -> bool {
    HARDWARE_ACCEL_ENABLED.load(Ordering::SeqCst)
}
pub fn aes_ni_available() -> bool {
    AES_NI_AVAILABLE.load(Ordering::SeqCst)
}
pub fn sha_ni_available() -> bool {
    SHA_NI_AVAILABLE.load(Ordering::SeqCst)
}
pub fn use_aes_ni() -> bool {
    is_enabled() && aes_ni_available()
}
pub fn use_sha_ni() -> bool {
    is_enabled() && sha_ni_available()
}
