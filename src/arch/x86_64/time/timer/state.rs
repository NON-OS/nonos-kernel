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

use core::sync::atomic::{AtomicU64, AtomicBool};
use spin::Mutex;
use alloc::{collections::BTreeMap, boxed::Box};

pub(crate) static BOOT_TIME: AtomicU64 = AtomicU64::new(0);
pub(crate) static TSC_FREQUENCY: AtomicU64 = AtomicU64::new(0);
pub(crate) static TIMER_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(crate) static HPET_BASE: AtomicU64 = AtomicU64::new(0);
pub(crate) static ACTIVE_TIMERS: Mutex<BTreeMap<u64, TimerCallback>> = Mutex::new(BTreeMap::new());
pub(crate) static NEXT_TIMER_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) struct TimerCallback {
    pub expiry_ns: u64,
    pub callback: Box<dyn Fn() + Send + Sync>,
}
