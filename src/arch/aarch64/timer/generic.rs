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

pub fn frequency() -> u64 {
    let freq: u64;
    unsafe {
        asm!("mrs {}, cntfrq_el0", out(reg) freq);
    }
    freq
}

pub fn current_count() -> u64 {
    let count: u64;
    unsafe {
        asm!("mrs {}, cntpct_el0", out(reg) count);
    }
    count
}

pub fn virtual_count() -> u64 {
    let count: u64;
    unsafe {
        asm!("mrs {}, cntvct_el0", out(reg) count);
    }
    count
}

pub fn nanoseconds_to_ticks(ns: u64) -> u64 {
    let freq = frequency();
    (ns * freq) / 1_000_000_000
}

pub fn ticks_to_nanoseconds(ticks: u64) -> u64 {
    let freq = frequency();
    if freq == 0 {
        return 0;
    }
    (ticks * 1_000_000_000) / freq
}

pub fn microseconds_to_ticks(us: u64) -> u64 {
    let freq = frequency();
    (us * freq) / 1_000_000
}

pub fn ticks_to_microseconds(ticks: u64) -> u64 {
    let freq = frequency();
    if freq == 0 {
        return 0;
    }
    (ticks * 1_000_000) / freq
}

pub fn milliseconds_to_ticks(ms: u64) -> u64 {
    let freq = frequency();
    (ms * freq) / 1_000
}

pub fn ticks_to_milliseconds(ticks: u64) -> u64 {
    let freq = frequency();
    if freq == 0 {
        return 0;
    }
    (ticks * 1_000) / freq
}

pub fn virtual_offset() -> u64 {
    let offset: u64;
    unsafe {
        asm!("mrs {}, cntvoff_el2", out(reg) offset);
    }
    offset
}

pub fn physical_to_virtual(phys_count: u64) -> u64 {
    phys_count.wrapping_sub(virtual_offset())
}

pub fn virtual_to_physical(virt_count: u64) -> u64 {
    virt_count.wrapping_add(virtual_offset())
}
