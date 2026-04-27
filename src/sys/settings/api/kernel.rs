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

use crate::sys::settings::state::get_mut;

pub fn kernel_aslr() -> bool {
    get_mut().kernel_aslr
}
pub fn set_kernel_aslr(v: bool) {
    get_mut().kernel_aslr = v;
    apply_aslr(v);
}

pub fn kernel_stack_guard() -> bool {
    get_mut().kernel_stack_guard
}
pub fn set_kernel_stack_guard(v: bool) {
    get_mut().kernel_stack_guard = v;
}

pub fn kernel_nx_bit() -> bool {
    get_mut().kernel_nx_bit
}
pub fn set_kernel_nx_bit(v: bool) {
    get_mut().kernel_nx_bit = v;
    apply_nx(v);
}

pub fn kernel_smep() -> bool {
    get_mut().kernel_smep
}
pub fn set_kernel_smep(v: bool) {
    get_mut().kernel_smep = v;
    apply_smep(v);
}

pub fn kernel_smap() -> bool {
    get_mut().kernel_smap
}
pub fn set_kernel_smap(v: bool) {
    get_mut().kernel_smap = v;
    apply_smap(v);
}

pub fn kernel_debug() -> bool {
    get_mut().kernel_debug
}
pub fn set_kernel_debug(v: bool) {
    get_mut().kernel_debug = v;
    apply_debug(v);
}

pub fn kernel_serial() -> bool {
    get_mut().kernel_serial
}
pub fn set_kernel_serial(v: bool) {
    get_mut().kernel_serial = v;
}

pub fn kernel_watchdog() -> bool {
    get_mut().kernel_watchdog
}
pub fn set_kernel_watchdog(v: bool) {
    get_mut().kernel_watchdog = v;
    apply_watchdog(v);
}

pub fn kernel_preempt() -> bool {
    get_mut().kernel_preempt
}
pub fn set_kernel_preempt(v: bool) {
    get_mut().kernel_preempt = v;
}

pub fn kernel_hugepages() -> bool {
    get_mut().kernel_hugepages
}
pub fn set_kernel_hugepages(v: bool) {
    get_mut().kernel_hugepages = v;
}

pub fn kernel_iommu() -> bool {
    get_mut().kernel_iommu
}
pub fn set_kernel_iommu(v: bool) {
    get_mut().kernel_iommu = v;
}

pub fn kernel_seccomp() -> bool {
    get_mut().kernel_seccomp
}
pub fn set_kernel_seccomp(v: bool) {
    get_mut().kernel_seccomp = v;
}

fn apply_aslr(_enabled: bool) {
    crate::memory::paging::set_aslr_enabled(_enabled);
}

fn apply_nx(enabled: bool) {
    if enabled {
        unsafe {
            enable_nx_bit();
        }
    }
}

fn apply_smep(enabled: bool) {
    unsafe {
        let cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
        let new_cr4 = if enabled { cr4 | (1 << 20) } else { cr4 & !(1 << 20) };
        core::arch::asm!("mov cr4, {}", in(reg) new_cr4);
    }
}

fn apply_smap(enabled: bool) {
    unsafe {
        let cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
        let new_cr4 = if enabled { cr4 | (1 << 21) } else { cr4 & !(1 << 21) };
        core::arch::asm!("mov cr4, {}", in(reg) new_cr4);
    }
}

fn apply_debug(enabled: bool) {
    crate::sys::serial::set_debug_enabled(enabled);
}

fn apply_watchdog(enabled: bool) {
    if enabled {
        crate::arch::x86_64::watchdog::enable();
    } else {
        crate::arch::x86_64::watchdog::disable();
    }
}

unsafe fn enable_nx_bit() {
    let eax: u32;
    let edx: u32;
    core::arch::asm!("rdmsr", in("ecx") 0xC000_0080u32, out("eax") eax, out("edx") edx);
    let efer = ((edx as u64) << 32) | (eax as u64);
    let new_efer = efer | (1 << 11);
    core::arch::asm!("wrmsr", in("ecx") 0xC000_0080u32, in("eax") new_efer as u32, in("edx") (new_efer >> 32) as u32);
}
