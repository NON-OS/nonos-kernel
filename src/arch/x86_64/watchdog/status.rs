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
use crate::arch::x86_64::port::inw;
use super::constants::{TCO1_STS, TCO2_STS};
use super::state::{LAST_KICK, TIMEOUT_MS};
use super::detect::detect_tco_watchdog;
use super::ops::is_enabled;

#[derive(Debug, Clone, Copy)]
pub struct WatchdogStatus {
    pub enabled: bool,
    pub timeout_ms: u64,
    pub last_kick_ms: u64,
    pub tco_detected: bool,
    pub tco1_status: u16,
    pub tco2_status: u16,
}

pub fn get_status() -> WatchdogStatus {
    let (tco1_sts, tco2_sts) = if detect_tco_watchdog() {
        unsafe { (inw(TCO1_STS), inw(TCO2_STS)) }
    } else {
        (0, 0)
    };
    WatchdogStatus {
        enabled: is_enabled(),
        timeout_ms: TIMEOUT_MS.load(Ordering::Relaxed),
        last_kick_ms: LAST_KICK.load(Ordering::Relaxed),
        tco_detected: detect_tco_watchdog(),
        tco1_status: tco1_sts,
        tco2_status: tco2_sts,
    }
}
