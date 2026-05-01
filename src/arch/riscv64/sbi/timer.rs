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

use super::base::sbi_call;
use super::error::SbiError;

const EID_TIMER: usize = 0x54494D45;
const FID_SET_TIMER: usize = 0;

pub fn set_timer(stime_value: u64) -> Result<(), SbiError> {
    let ret = sbi_call(EID_TIMER, FID_SET_TIMER, stime_value as usize, 0, 0);

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(())
    }
}

pub fn set_timer_relative(delta: u64) -> Result<(), SbiError> {
    let current = super::super::timer::read_time();
    set_timer(current + delta)
}

pub fn clear_timer() -> Result<(), SbiError> {
    set_timer(u64::MAX)
}
