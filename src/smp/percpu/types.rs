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


use core::sync::atomic::AtomicU64;

#[repr(C, align(4096))]
pub struct PerCpuData {
    pub self_ptr: u64,
    pub cpu_id: u32,
    pub apic_id: u32,
    pub current_process: AtomicU64,
    pub current_thread: AtomicU64,
    pub kernel_stack_top: u64,
    pub user_stack_saved: u64,
    pub syscall_scratch: [u64; 4],
    pub irq_nesting: u32,
    pub sched_lock_held: u32,
    pub random_state: AtomicU64,
    pub last_tick_tsc: AtomicU64,
    pub interrupt_disable_depth: u32,
    _reserved: [u8; 4096 - 112],
}

impl PerCpuData {
    pub const fn new() -> Self {
        Self {
            self_ptr: 0,
            cpu_id: 0,
            apic_id: 0,
            current_process: AtomicU64::new(0),
            current_thread: AtomicU64::new(0),
            kernel_stack_top: 0,
            user_stack_saved: 0,
            syscall_scratch: [0; 4],
            irq_nesting: 0,
            sched_lock_held: 0,
            random_state: AtomicU64::new(0),
            last_tick_tsc: AtomicU64::new(0),
            interrupt_disable_depth: 0,
            _reserved: [0; 4096 - 112],
        }
    }
}
