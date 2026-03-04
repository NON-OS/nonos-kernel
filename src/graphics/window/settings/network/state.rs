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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::Mutex;
use crate::drivers::wifi::ScanResult;
use crate::sys::settings::network as net_settings;
use crate::graphics::window::settings::state::SETTING_DHCP_ENABLED;

pub static WIFI_SCANNING: AtomicBool = AtomicBool::new(false);
pub static SELECTED_NETWORK: AtomicU8 = AtomicU8::new(255);
pub static SHOW_PASSWORD_DIALOG: AtomicBool = AtomicBool::new(false);
pub static CACHED_SCAN_RESULTS: Mutex<Vec<ScanResult>> = Mutex::new(Vec::new());
pub static PASSWORD_BUFFER: Mutex<[u8; 64]> = Mutex::new([0u8; 64]);
pub static PASSWORD_LEN: AtomicU8 = AtomicU8::new(0);
pub static CONNECTING: AtomicBool = AtomicBool::new(false);
pub static CONNECTION_ERROR: Mutex<Option<&'static str>> = Mutex::new(None);
pub static LOADING_FIRMWARE: AtomicBool = AtomicBool::new(false);

pub(crate) fn sync_from_system() {
    let settings = net_settings::get_settings();
    SETTING_DHCP_ENABLED.store(settings.dhcp_enabled, Ordering::Relaxed);
}
