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

use uefi::prelude::*;

pub fn read_tsc() -> u64 {
    // ## SAFETY: RDTSC is always available on x86_64
    unsafe { core::arch::x86_64::_rdtsc() }
}

pub fn get_uefi_time_epoch(st: &SystemTable<Boot>) -> u64 {
    if let Ok(time) = st.runtime_services().get_time() {
        let year = time.year() as u64;
        let month = time.month() as u64;
        let day = time.day() as u64;
        let hour = time.hour() as u64;
        let minute = time.minute() as u64;
        let second = time.second() as u64;
        let days_since_epoch = (year - 1970) * 365 + (year - 1969) / 4 - (year - 1901) / 100
            + (year - 1601) / 400
            + (367 * month - 362) / 12
            + day
            - 1;

        let leap_adjust = if month <= 2 {
            0
        } else if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
            2
        } else {
            1
        };

        let total_days = days_since_epoch - leap_adjust;
        (total_days * 86400 + hour * 3600 + minute * 60 + second) * 1000
    } else {
        0
    }
}
