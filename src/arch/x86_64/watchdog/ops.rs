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
use crate::arch::x86_64::port::{outb, inw, outw};
use super::constants::{TCO_RLD, TCO1_CNT};
use super::state::{ENABLED, LAST_KICK, TIMEOUT_MS};
use super::detect::detect_tco_watchdog;

pub fn enable() {
    if detect_tco_watchdog() {
        unsafe {
            let cnt = inw(TCO1_CNT);
            outw(TCO1_CNT, cnt & !0x0800);
            outb(TCO_RLD, 0x01);
        }
        ENABLED.store(true, Ordering::SeqCst);
        kick();
    }
}

pub fn disable() {
    if ENABLED.load(Ordering::Relaxed) {
        unsafe {
            let cnt = inw(TCO1_CNT);
            outw(TCO1_CNT, cnt | 0x0800);
        }
        ENABLED.store(false, Ordering::SeqCst);
    }
}

pub fn kick() {
    if ENABLED.load(Ordering::Relaxed) {
        unsafe { outb(TCO_RLD, 0x01); }
        LAST_KICK.store(crate::sys::clock::unix_ms(), Ordering::Relaxed);
    }
}

pub fn is_enabled() -> bool { ENABLED.load(Ordering::Relaxed) }

pub fn set_timeout(ms: u64) { TIMEOUT_MS.store(ms, Ordering::Relaxed); }
pub fn get_timeout() -> u64 { TIMEOUT_MS.load(Ordering::Relaxed) }
