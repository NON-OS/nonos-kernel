// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for arch/x86_64/time

use crate::arch::x86_64::time::{PIT_FREQUENCY, RtcRegister};

#[test_case]
fn test_pit_frequency() {
    assert_eq!(PIT_FREQUENCY, 1193182);
}

#[test_case]
fn test_pit_frequency_approximately_1mhz() {
    assert!(PIT_FREQUENCY > 1_000_000);
    assert!(PIT_FREQUENCY < 2_000_000);
}

#[test_case]
fn test_rtc_register_seconds() {
    assert_eq!(RtcRegister::Seconds as u8, 0x00);
}

#[test_case]
fn test_rtc_register_minutes() {
    assert_eq!(RtcRegister::Minutes as u8, 0x02);
}

#[test_case]
fn test_rtc_register_hours() {
    assert_eq!(RtcRegister::Hours as u8, 0x04);
}

#[test_case]
fn test_rtc_register_day_of_week() {
    assert_eq!(RtcRegister::DayOfWeek as u8, 0x06);
}

#[test_case]
fn test_rtc_register_day() {
    assert_eq!(RtcRegister::Day as u8, 0x07);
}

#[test_case]
fn test_rtc_register_month() {
    assert_eq!(RtcRegister::Month as u8, 0x08);
}

#[test_case]
fn test_rtc_register_year() {
    assert_eq!(RtcRegister::Year as u8, 0x09);
}

#[test_case]
fn test_rtc_register_status_a() {
    assert_eq!(RtcRegister::StatusA as u8, 0x0A);
}

#[test_case]
fn test_rtc_register_status_b() {
    assert_eq!(RtcRegister::StatusB as u8, 0x0B);
}

#[test_case]
fn test_rtc_register_century() {
    assert_eq!(RtcRegister::Century as u8, 0x32);
}
