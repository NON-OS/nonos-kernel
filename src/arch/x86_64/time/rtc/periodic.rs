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

use super::constants::{Register, status_a, status_b};
use super::error::RtcResult;
use super::types::PeriodicRate;
use super::cmos::{cmos_read, cmos_write};
use super::state::RTC_STATE;

pub fn set_periodic_rate(rate: PeriodicRate) -> RtcResult<()> {
    let status_a_val = cmos_read(Register::StatusA as u8);
    let new_status_a = (status_a_val & !status_a::RATE_MASK) | rate.value();
    cmos_write(Register::StatusA as u8, new_status_a);

    let mut state = RTC_STATE.write();
    state.periodic_rate = rate;

    Ok(())
}

pub fn enable_periodic() -> RtcResult<()> {
    let status_b_val = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b_val | status_b::PIE);

    let mut state = RTC_STATE.write();
    state.periodic_enabled = true;

    Ok(())
}

pub fn disable_periodic() {
    let status_b_val = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b_val & !status_b::PIE);

    let mut state = RTC_STATE.write();
    state.periodic_enabled = false;
}

pub fn is_periodic_enabled() -> bool {
    RTC_STATE.read().periodic_enabled
}

pub fn get_periodic_rate() -> PeriodicRate {
    RTC_STATE.read().periodic_rate
}
