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
use super::constants::{Register, status_b, status_c};
use super::error::RtcResult;
use super::cmos::{cmos_read, cmos_write};
use super::state::{RTC_STATE, STATS_UPDATE_INTS, STATS_ALARM_INTS, STATS_PERIODIC_INTS};

pub fn enable_update_interrupt() -> RtcResult<()> {
    let status_b_val = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b_val | status_b::UIE);

    let mut state = RTC_STATE.write();
    state.update_enabled = true;

    Ok(())
}

pub fn disable_update_interrupt() {
    let status_b_val = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b_val & !status_b::UIE);

    let mut state = RTC_STATE.write();
    state.update_enabled = false;
}

pub fn is_update_interrupt_enabled() -> bool {
    RTC_STATE.read().update_enabled
}

pub fn handle_interrupt() -> u8 {
    let status_c_val = cmos_read(Register::StatusC as u8);

    if (status_c_val & status_c::UF) != 0 {
        STATS_UPDATE_INTS.fetch_add(1, Ordering::Relaxed);
    }

    if (status_c_val & status_c::AF) != 0 {
        STATS_ALARM_INTS.fetch_add(1, Ordering::Relaxed);
    }

    if (status_c_val & status_c::PF) != 0 {
        STATS_PERIODIC_INTS.fetch_add(1, Ordering::Relaxed);
    }

    status_c_val
}

pub fn check_interrupt_source() -> (bool, bool, bool) {
    let status_c_val = cmos_read(Register::StatusC as u8);
    (
        (status_c_val & status_c::UF) != 0,
        (status_c_val & status_c::AF) != 0,
        (status_c_val & status_c::PF) != 0,
    )
}
