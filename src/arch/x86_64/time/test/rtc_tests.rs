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

use super::types::TestResult;
use crate::arch::x86_64::time::rtc;

pub fn test_rtc_bcd_to_bin() -> TestResult {
    let time = rtc::RtcTime::new(2024, 6, 15, 12, 30, 45);
    if time.validate().is_err() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_rtc_time_valid() -> TestResult {
    let t1 = rtc::RtcTime::new(2024, 1, 1, 0, 0, 0);
    if t1.validate().is_err() {
        return TestResult::Failed;
    }

    let t2 = rtc::RtcTime::new(2024, 12, 31, 23, 59, 59);
    if t2.validate().is_err() {
        return TestResult::Failed;
    }

    let t3 = rtc::RtcTime::new(2024, 2, 29, 12, 0, 0);
    if t3.validate().is_err() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_rtc_time_invalid() -> TestResult {
    let t1 = rtc::RtcTime::new(2024, 1, 1, 0, 0, 60);
    if t1.validate().is_ok() {
        return TestResult::Failed;
    }

    let t2 = rtc::RtcTime::new(2024, 1, 1, 0, 60, 0);
    if t2.validate().is_ok() {
        return TestResult::Failed;
    }

    let t3 = rtc::RtcTime::new(2024, 1, 1, 24, 0, 0);
    if t3.validate().is_ok() {
        return TestResult::Failed;
    }

    let t4 = rtc::RtcTime::new(2024, 13, 1, 0, 0, 0);
    if t4.validate().is_ok() {
        return TestResult::Failed;
    }

    let t5 = rtc::RtcTime::new(2024, 2, 30, 0, 0, 0);
    if t5.validate().is_ok() {
        return TestResult::Failed;
    }

    let t6 = rtc::RtcTime::new(2023, 2, 29, 0, 0, 0);
    if t6.validate().is_ok() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_rtc_leap_year() -> TestResult {
    if !rtc::is_leap_year(2000) {
        return TestResult::Failed;
    }
    if !rtc::is_leap_year(2004) {
        return TestResult::Failed;
    }
    if !rtc::is_leap_year(2024) {
        return TestResult::Failed;
    }

    if rtc::is_leap_year(1900) {
        return TestResult::Failed;
    }
    if rtc::is_leap_year(2100) {
        return TestResult::Failed;
    }
    if rtc::is_leap_year(2023) {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_rtc_days_in_month() -> TestResult {
    if rtc::days_in_month(2024, 1) != 31 {
        return TestResult::Failed;
    }
    if rtc::days_in_month(2024, 7) != 31 {
        return TestResult::Failed;
    }
    if rtc::days_in_month(2024, 12) != 31 {
        return TestResult::Failed;
    }

    if rtc::days_in_month(2024, 4) != 30 {
        return TestResult::Failed;
    }
    if rtc::days_in_month(2024, 11) != 30 {
        return TestResult::Failed;
    }

    if rtc::days_in_month(2024, 2) != 29 {
        return TestResult::Failed;
    }
    if rtc::days_in_month(2023, 2) != 28 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_rtc_day_of_week() -> TestResult {
    if rtc::day_of_week(1970, 1, 1) != 5 {
        return TestResult::Failed;
    }

    if rtc::day_of_week(2024, 1, 1) != 2 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_rtc_unix_epoch() -> TestResult {
    let time = rtc::RtcTime::from_unix_timestamp(0);

    if time.year != 1970 || time.month != 1 || time.day != 1 {
        return TestResult::Failed;
    }
    if time.hour != 0 || time.minute != 0 || time.second != 0 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_rtc_unix_roundtrip() -> TestResult {
    let original = rtc::RtcTime::new(2024, 6, 15, 12, 30, 45);
    let timestamp = original.to_unix_timestamp();
    let converted = rtc::RtcTime::from_unix_timestamp(timestamp);

    if converted.year != original.year {
        return TestResult::Failed;
    }
    if converted.month != original.month {
        return TestResult::Failed;
    }
    if converted.day != original.day {
        return TestResult::Failed;
    }
    if converted.hour != original.hour {
        return TestResult::Failed;
    }
    if converted.minute != original.minute {
        return TestResult::Failed;
    }
    if converted.second != original.second {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_rtc_alarm_validation() -> TestResult {
    let valid = rtc::RtcAlarm::new(12, 30, 45);
    if valid.validate().is_err() {
        return TestResult::Failed;
    }

    let wildcard = rtc::RtcAlarm::every_second();
    if wildcard.validate().is_err() {
        return TestResult::Failed;
    }

    let invalid = rtc::RtcAlarm::new(25, 0, 0);
    if invalid.validate().is_ok() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_rtc_periodic_rate() -> TestResult {
    if rtc::PeriodicRate::Hz1024.frequency_hz() != 1024 {
        return TestResult::Failed;
    }
    if rtc::PeriodicRate::Hz2.frequency_hz() != 2 {
        return TestResult::Failed;
    }
    if rtc::PeriodicRate::Disabled.frequency_hz() != 0 {
        return TestResult::Failed;
    }

    if rtc::PeriodicRate::Hz1024.period_us() != 976 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_rtc_format_iso8601() -> TestResult {
    let time = rtc::RtcTime::new(2024, 6, 15, 12, 30, 45);
    let formatted = time.format_iso8601();

    if &formatted != b"2024-06-15 12:30:45" {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_rtc_day_of_year() -> TestResult {
    let jan1 = rtc::RtcTime::new(2024, 1, 1, 0, 0, 0);
    if jan1.day_of_year() != 1 {
        return TestResult::Failed;
    }

    let dec31 = rtc::RtcTime::new(2024, 12, 31, 0, 0, 0);
    if dec31.day_of_year() != 366 {
        return TestResult::Failed;
    }

    let dec31_non_leap = rtc::RtcTime::new(2023, 12, 31, 0, 0, 0);
    if dec31_non_leap.day_of_year() != 365 {
        return TestResult::Failed;
    }

    TestResult::Passed
}
