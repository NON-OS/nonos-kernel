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

use core::sync::atomic::Ordering;
use super::types::SecureBootPolicy;
use super::state::{SECURE_BOOT_ENFORCED, CURRENT_POLICY};

pub fn set_policy(policy: SecureBootPolicy) {
    let mut current = CURRENT_POLICY.lock();
    *current = policy;

    match policy {
        SecureBootPolicy::Enforcing | SecureBootPolicy::Strict => {
            SECURE_BOOT_ENFORCED.store(true, Ordering::SeqCst);
            crate::log::log_warning!("[SECURE_BOOT] Enforcement ENABLED - unsigned code will be BLOCKED");
        }
        SecureBootPolicy::Permissive => {
            SECURE_BOOT_ENFORCED.store(false, Ordering::SeqCst);
            crate::log::log_warning!("[SECURE_BOOT] Permissive mode - violations logged but not blocked");
        }
        SecureBootPolicy::Disabled => {
            SECURE_BOOT_ENFORCED.store(false, Ordering::SeqCst);
            crate::log::error!("[SECURE_BOOT] DISABLED - THIS IS DANGEROUS!");
        }
    }
}

pub fn get_policy() -> SecureBootPolicy {
    *CURRENT_POLICY.lock()
}

pub fn is_enforcing() -> bool {
    SECURE_BOOT_ENFORCED.load(Ordering::SeqCst)
}
