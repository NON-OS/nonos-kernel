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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use super::port::{outb, inw, outw};

static ENABLED: AtomicBool = AtomicBool::new(false);
static LAST_KICK: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_MS: AtomicU64 = AtomicU64::new(30000);

const TCO_RLD: u16 = 0x460;
const TCO1_CNT: u16 = 0x468;
const TCO1_STS: u16 = 0x464;
const TCO2_STS: u16 = 0x466;

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

fn detect_tco_watchdog() -> bool {
    if let Some(lpc) = crate::bus::pci::find_device(0x06, 0x01, None) {
        let vendor = lpc.vendor_id;
        vendor == 0x8086
    } else {
        false
    }
}

pub fn get_status() -> WatchdogStatus {
    let (tco1_sts, tco2_sts) = if detect_tco_watchdog() {
        unsafe { (inw(TCO1_STS), inw(TCO2_STS)) }
    } else {
        (0, 0)
    };
    WatchdogStatus {
        enabled: is_enabled(),
        timeout_ms: get_timeout(),
        last_kick_ms: LAST_KICK.load(Ordering::Relaxed),
        tco_detected: detect_tco_watchdog(),
        tco1_status: tco1_sts,
        tco2_status: tco2_sts,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WatchdogStatus {
    pub enabled: bool,
    pub timeout_ms: u64,
    pub last_kick_ms: u64,
    pub tco_detected: bool,
    pub tco1_status: u16,
    pub tco2_status: u16,
}
