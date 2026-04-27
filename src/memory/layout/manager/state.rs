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

use super::super::constants::*;
use super::super::types::*;
use spin::RwLock;

pub(super) static LAYOUT: RwLock<LayoutConfig> = RwLock::new(LayoutConfig {
    slide: 0,
    heap_lo: KHEAP_BASE,
    heap_sz: KHEAP_SIZE,
    vm_lo: KVM_BASE,
    vm_sz: KVM_SIZE,
    mmio_lo: MMIO_BASE,
    mmio_sz: MMIO_SIZE,
    initialized: false,
});

extern "C" {
    pub(super) static __kernel_start: u8;
    static __kernel_text_start: u8;
    static __kernel_text_end: u8;
    static __kernel_rodata_start: u8;
    static __kernel_rodata_end: u8;
    static __kernel_data_start: u8;
    static __kernel_data_end: u8;
    static __kernel_bss_start: u8;
    static __kernel_bss_end: u8;
    pub(super) static __kernel_end: u8;
    static __boot_stacks_start: u8;
    static __boot_stacks_end: u8;
    static __percpu_start: u8;
    static __percpu_end: u8;
}

pub fn kernel_sections() -> [Section; KERNEL_SECTION_COUNT] {
    unsafe {
        [
            Section {
                start: &__kernel_text_start as *const _ as u64,
                end: &__kernel_text_end as *const _ as u64,
                rx: true,
                rw: false,
                nx: false,
                global: true,
            },
            Section {
                start: &__kernel_rodata_start as *const _ as u64,
                end: &__kernel_rodata_end as *const _ as u64,
                rx: false,
                rw: false,
                nx: true,
                global: true,
            },
            Section {
                start: &__kernel_data_start as *const _ as u64,
                end: &__kernel_data_end as *const _ as u64,
                rx: false,
                rw: true,
                nx: true,
                global: true,
            },
            Section {
                start: &__kernel_bss_start as *const _ as u64,
                end: &__kernel_bss_end as *const _ as u64,
                rx: false,
                rw: true,
                nx: true,
                global: true,
            },
        ]
    }
}

pub fn kernel_start() -> u64 {
    unsafe { &__kernel_start as *const _ as u64 }
}
pub fn kernel_end() -> u64 {
    unsafe { &__kernel_end as *const _ as u64 }
}
pub fn boot_stacks_region() -> (u64, u64) {
    unsafe { (&__boot_stacks_start as *const _ as u64, &__boot_stacks_end as *const _ as u64) }
}
pub fn percpu_template_region() -> (u64, u64) {
    unsafe { (&__percpu_start as *const _ as u64, &__percpu_end as *const _ as u64) }
}
