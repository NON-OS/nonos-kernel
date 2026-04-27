// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static BATTERY_PERCENT: AtomicU8 = AtomicU8::new(100);
static BATTERY_CHARGING: AtomicBool = AtomicBool::new(false);
static BATTERY_PRESENT: AtomicBool = AtomicBool::new(true);
static AC_CONNECTED: AtomicBool = AtomicBool::new(true);

#[derive(Clone, Copy, PartialEq)]
pub enum BatteryState {
    Full,
    Charging,
    Discharging,
    NotPresent,
}

pub fn get_battery_percent() -> u8 {
    BATTERY_PERCENT.load(Ordering::Relaxed)
}
pub fn is_charging() -> bool {
    BATTERY_CHARGING.load(Ordering::Relaxed)
}
pub fn is_battery_present() -> bool {
    BATTERY_PRESENT.load(Ordering::Relaxed)
}
pub fn is_ac_connected() -> bool {
    AC_CONNECTED.load(Ordering::Relaxed)
}

pub fn get_battery_state() -> BatteryState {
    if !is_battery_present() {
        return BatteryState::NotPresent;
    }
    if is_charging() {
        return BatteryState::Charging;
    }
    if get_battery_percent() >= 95 && is_ac_connected() {
        return BatteryState::Full;
    }
    BatteryState::Discharging
}

pub fn update_battery_status() {
    if let Some((percent, charging, ac)) = read_acpi_battery() {
        BATTERY_PERCENT.store(percent, Ordering::Relaxed);
        BATTERY_CHARGING.store(charging, Ordering::Relaxed);
        AC_CONNECTED.store(ac, Ordering::Relaxed);
    }
}

fn read_acpi_battery() -> Option<(u8, bool, bool)> {
    unsafe {
        let ec_data = crate::arch::x86_64::port::inb(0x66);
        let charging = (ec_data & 0x01) != 0;
        let ac = (ec_data & 0x02) != 0;
        let smc_result = read_battery_smc();
        let percent = smc_result.unwrap_or(100);
        Some((percent, charging, ac))
    }
}

fn read_battery_smc() -> Option<u8> {
    unsafe {
        let status = crate::arch::x86_64::port::inb(0x66);
        if status & 0x01 == 0 {
            return None;
        }
        crate::arch::x86_64::port::outb(0x66, 0x80);
        for _ in 0..1000 {
            if crate::arch::x86_64::port::inb(0x66) & 0x02 == 0 {
                break;
            }
        }
        crate::arch::x86_64::port::outb(0x62, 0x01);
        for _ in 0..1000 {
            if crate::arch::x86_64::port::inb(0x66) & 0x01 != 0 {
                break;
            }
        }
        let value = crate::arch::x86_64::port::inb(0x62);
        Some(value.min(100))
    }
}

pub fn init() {
    BATTERY_PRESENT.store(detect_battery(), Ordering::Relaxed);
    update_battery_status();
}

fn detect_battery() -> bool {
    crate::arch::x86_64::acpi::power::is_mobile()
}
