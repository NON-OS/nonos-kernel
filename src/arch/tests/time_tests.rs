// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::arch::x86_64::time::{RtcRegister, PIT_FREQUENCY};
use crate::test::framework::TestResult;

pub(crate) fn test_pit_frequency() -> TestResult {
    if PIT_FREQUENCY != 1193182 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pit_frequency_approximately_1mhz() -> TestResult {
    if PIT_FREQUENCY <= 1_000_000 {
        return TestResult::Fail;
    }
    if PIT_FREQUENCY >= 2_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rtc_register_seconds() -> TestResult {
    if RtcRegister::Seconds as u8 != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rtc_register_minutes() -> TestResult {
    if RtcRegister::Minutes as u8 != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rtc_register_hours() -> TestResult {
    if RtcRegister::Hours as u8 != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rtc_register_day_of_week() -> TestResult {
    if RtcRegister::DayOfWeek as u8 != 0x06 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rtc_register_day() -> TestResult {
    if RtcRegister::Day as u8 != 0x07 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rtc_register_month() -> TestResult {
    if RtcRegister::Month as u8 != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rtc_register_year() -> TestResult {
    if RtcRegister::Year as u8 != 0x09 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rtc_register_status_a() -> TestResult {
    if RtcRegister::StatusA as u8 != 0x0A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rtc_register_status_b() -> TestResult {
    if RtcRegister::StatusB as u8 != 0x0B {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rtc_register_century() -> TestResult {
    if RtcRegister::Century as u8 != 0x32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
