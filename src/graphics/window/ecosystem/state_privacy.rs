// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use spin::Mutex;

pub static LP_TOTAL_VALUE: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
pub static LP_TOTAL_VALUE_LEN: AtomicUsize = AtomicUsize::new(0);
pub static LP_APY: Mutex<[u8; 16]> = Mutex::new([0u8; 16]);
pub static LP_APY_LEN: AtomicUsize = AtomicUsize::new(0);
pub static NODE_CONNECTED: AtomicBool = AtomicBool::new(false);
pub static NODE_PEERS: AtomicUsize = AtomicUsize::new(0);
pub static NODE_BLOCK_HEIGHT: AtomicUsize = AtomicUsize::new(0);
pub static NODE_SYNC_PROGRESS: AtomicU8 = AtomicU8::new(0);
pub static PRIVACY_TRACKERS_BLOCKED: AtomicUsize = AtomicUsize::new(0);
pub static PRIVACY_ADS_BLOCKED: AtomicUsize = AtomicUsize::new(0);
pub static PRIVACY_URLS_CLEANED: AtomicUsize = AtomicUsize::new(0);

use core::sync::atomic::AtomicBool;

pub fn increment_trackers_blocked() {
    PRIVACY_TRACKERS_BLOCKED.fetch_add(1, Ordering::Relaxed);
}
pub fn increment_ads_blocked() {
    PRIVACY_ADS_BLOCKED.fetch_add(1, Ordering::Relaxed);
}
pub fn increment_urls_cleaned() {
    PRIVACY_URLS_CLEANED.fetch_add(1, Ordering::Relaxed);
}
