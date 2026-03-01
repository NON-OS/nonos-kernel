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

use core::sync::atomic::{AtomicBool, AtomicU64};
use spin::{Mutex, RwLock};
use super::types::{BootMeasurements, TrustedBootKeys, SecureBootPolicy};

pub static SECURE_BOOT_ENFORCED: AtomicBool = AtomicBool::new(false);
pub static SECURE_BOOT_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static BOOT_CHAIN_VERIFIED: AtomicBool = AtomicBool::new(false);
pub static VIOLATION_COUNT: AtomicU64 = AtomicU64::new(0);

pub static BOOT_MEASUREMENTS: RwLock<BootMeasurements> = RwLock::new(BootMeasurements::new());
pub static TRUSTED_BOOT_KEYS: RwLock<TrustedBootKeys> = RwLock::new(TrustedBootKeys::new());
pub static CURRENT_POLICY: Mutex<SecureBootPolicy> = Mutex::new(SecureBootPolicy::Permissive);
