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

pub struct PhysicalTimer;

impl PhysicalTimer {
    pub fn enable() {
        unsafe {
            asm!("msr cntp_ctl_el0, {}", in(reg) 1u64);
        }
    }

    pub fn disable() {
        unsafe {
            asm!("msr cntp_ctl_el0, {}", in(reg) 0u64);
        }
    }

    pub fn mask_interrupt() {
        unsafe {
            asm!("msr cntp_ctl_el0, {}", in(reg) 0b11u64);
        }
    }

    pub fn unmask_interrupt() {
        unsafe {
            asm!("msr cntp_ctl_el0, {}", in(reg) 1u64);
        }
    }

    pub fn is_pending() -> bool {
        let ctl: u64;
        unsafe {
            asm!("mrs {}, cntp_ctl_el0", out(reg) ctl);
        }
        (ctl & (1 << 2)) != 0
    }

    pub fn set_compare_value(value: u64) {
        unsafe {
            asm!("msr cntp_cval_el0, {}", in(reg) value);
        }
    }

    pub fn get_compare_value() -> u64 {
        let cval: u64;
        unsafe {
            asm!("mrs {}, cntp_cval_el0", out(reg) cval);
        }
        cval
    }

    pub fn set_tval(tval: i32) {
        unsafe {
            asm!("msr cntp_tval_el0, {}", in(reg) tval as u64);
        }
    }

    pub fn get_tval() -> i32 {
        let tval: u64;
        unsafe {
            asm!("mrs {}, cntp_tval_el0", out(reg) tval);
        }
        tval as i32
    }

    pub fn set_relative(ticks: u64) {
        let current = super::generic::current_count();
        Self::set_compare_value(current + ticks);
        Self::enable();
    }
}

pub fn set_physical_timer(ticks: u64) {
    PhysicalTimer::set_relative(ticks);
}

pub fn clear_physical_timer() {
    PhysicalTimer::disable();
}

pub fn physical_timer_pending() -> bool {
    PhysicalTimer::is_pending()
}
