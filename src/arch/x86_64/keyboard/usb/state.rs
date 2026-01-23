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

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::{Mutex, RwLock};

use super::device::HidDeviceState;
use super::types::{UsbHidStats, MAX_HID_DEVICES};

pub static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static DEVICE_COUNT: AtomicU8 = AtomicU8::new(0);

pub static DEVICES: Mutex<[HidDeviceState; MAX_HID_DEVICES]> = Mutex::new([
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
]);

pub static STATS: RwLock<UsbHidStats> = RwLock::new(UsbHidStats::new());

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

#[inline]
pub fn device_count() -> u8 {
    DEVICE_COUNT.load(Ordering::Acquire)
}

#[inline]
pub fn get_stats() -> UsbHidStats {
    *STATS.read()
}

#[inline]
pub fn reset_stats() {
    *STATS.write() = UsbHidStats::new();
}
