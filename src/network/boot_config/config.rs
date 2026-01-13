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

use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};

use super::types::NetworkBootConfig;

/// *** Network boot configuration - set once at boot, immutable after *** ///
pub(super) static BOOT_CONFIG: Once<Mutex<NetworkBootConfig>> = Once::new();
pub(super) static CONFIG_LOCKED: AtomicBool = AtomicBool::new(false);
pub fn init() {
    BOOT_CONFIG.call_once(|| Mutex::new(NetworkBootConfig::default()));
    crate::log::info!("net: boot configuration system initialized");
}

pub fn configure() -> Option<spin::MutexGuard<'static, NetworkBootConfig>> {
    if CONFIG_LOCKED.load(Ordering::SeqCst) {
        crate::log_warn!("net: boot config is locked, cannot modify");
        return None;
    }
    BOOT_CONFIG.get().map(|m| m.lock())
}

pub fn get_config() -> Option<NetworkBootConfig> {
    BOOT_CONFIG.get().map(|m| m.lock().clone())
}

pub fn lock_config() -> bool {
    if CONFIG_LOCKED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        crate::log::info!("net: boot configuration locked for session");
        true
    } else {
        false
    }
}

pub fn is_locked() -> bool {
    CONFIG_LOCKED.load(Ordering::SeqCst)
}
