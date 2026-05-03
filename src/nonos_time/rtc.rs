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

use core::arch::asm;

const RTC_SECONDS: u8 = 0x00;
const RTC_MINUTES: u8 = 0x02;
const RTC_HOURS: u8 = 0x04;
const RTC_DAY: u8 = 0x07;
const RTC_MONTH: u8 = 0x08;
const RTC_YEAR: u8 = 0x09;
const RTC_STATUS_A: u8 = 0x0A;
const RTC_STATUS_B: u8 = 0x0B;

unsafe fn read_cmos(reg: u8) -> u8 {
    asm!("out 0x70, al", in("al") reg, options(nostack, nomem));
    let mut value: u8;
    asm!("in al, 0x71", out("al") value, options(nostack, nomem));
    value
}

fn bcd_to_binary(bcd: u8) -> u8 {
    ((bcd >> 4) * 10) + (bcd & 0x0F)
}

pub fn read_rtc_time() -> (u8, u8, u8, u8, u8, u8) {
    unsafe {
        while (read_cmos(RTC_STATUS_A) & 0x80) != 0 {
            core::hint::spin_loop();
        }
        let (sec, min, hr, d, m, y) = (
            read_cmos(RTC_SECONDS),
            read_cmos(RTC_MINUTES),
            read_cmos(RTC_HOURS),
            read_cmos(RTC_DAY),
            read_cmos(RTC_MONTH),
            read_cmos(RTC_YEAR),
        );
        let status_b = read_cmos(RTC_STATUS_B);
        if (status_b & 0x04) == 0 {
            (
                bcd_to_binary(sec),
                bcd_to_binary(min),
                bcd_to_binary(hr),
                bcd_to_binary(d),
                bcd_to_binary(m),
                bcd_to_binary(y),
            )
        } else {
            (sec, min, hr, d, m, y)
        }
    }
}

pub fn rtc_to_unix_timestamp() -> u64 {
    let (sec, min, hour, day, month, year) = read_rtc_time();
    let full_year = if year < 50 { 2000 + year as u32 } else { 1900 + year as u32 };
    const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut days = 0u32;
    for y in 1970..full_year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    for m in 1..month as u32 {
        days += DAYS_IN_MONTH[(m - 1) as usize];
        if m == 2 && is_leap_year(full_year) {
            days += 1;
        }
    }
    days += (day as u32) - 1;
    ((days as u64) * 86400 + (hour as u64) * 3600 + (min as u64) * 60 + (sec as u64)) * 1000
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

pub fn handle_interrupt() {
    unsafe {
        read_cmos(RTC_STATUS_A);
        read_cmos(RTC_STATUS_B);
    }
}
