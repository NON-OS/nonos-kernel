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

use super::asm::rdtsc;
use super::conversion::{ticks_to_ns, ticks_to_us, ticks_to_ms};
use super::state::CALIBRATION;

pub fn elapsed_ns() -> u64 {
    let cal = CALIBRATION.read();
    if cal.frequency_hz == 0 {
        return 0;
    }
    let current = rdtsc();
    let elapsed = current.saturating_sub(cal.boot_tsc);
    ticks_to_ns(elapsed)
}

pub fn elapsed_us() -> u64 {
    let cal = CALIBRATION.read();
    if cal.frequency_hz == 0 {
        return 0;
    }
    let current = rdtsc();
    let elapsed = current.saturating_sub(cal.boot_tsc);
    ticks_to_us(elapsed)
}

pub fn elapsed_ms() -> u64 {
    let cal = CALIBRATION.read();
    if cal.frequency_hz == 0 {
        return 0;
    }
    let current = rdtsc();
    let elapsed = current.saturating_sub(cal.boot_tsc);
    ticks_to_ms(elapsed)
}

pub fn elapsed_secs() -> u64 {
    elapsed_ms() / 1000
}
