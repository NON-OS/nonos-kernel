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

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CpuState {
    Offline = 0,
    Starting = 1,
    Online = 2,
    GoingOffline = 3,
    Halted = 4,
}

impl From<u8> for CpuState {
    fn from(v: u8) -> Self {
        match v {
            0 => CpuState::Offline,
            1 => CpuState::Starting,
            2 => CpuState::Online,
            3 => CpuState::GoingOffline,
            4 => CpuState::Halted,
            _ => CpuState::Offline,
        }
    }
}

#[repr(C, align(64))]
pub struct CpuDescriptor {
    pub cpu_id: u32,
    pub apic_id: u32,
    state: AtomicU32,
    pub numa_node: u32,
    pub stack_base: AtomicU64,
    pub stack_size: usize,
    pub idle_cycles: AtomicU64,
    pub total_cycles: AtomicU64,
    pub current_pid: AtomicU32,
    pub ipi_pending: AtomicU32,
    pub tlb_shootdown_pending: AtomicBool,
    pub preempt_disable_count: AtomicU32,
    pub in_interrupt: AtomicBool,
    pub last_error: AtomicU32,
    _pad: [u8; 4],
}

impl CpuDescriptor {
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            apic_id: 0,
            state: AtomicU32::new(CpuState::Offline as u32),
            numa_node: 0,
            stack_base: AtomicU64::new(0),
            stack_size: 0,
            idle_cycles: AtomicU64::new(0),
            total_cycles: AtomicU64::new(0),
            current_pid: AtomicU32::new(0),
            ipi_pending: AtomicU32::new(0),
            tlb_shootdown_pending: AtomicBool::new(false),
            preempt_disable_count: AtomicU32::new(0),
            in_interrupt: AtomicBool::new(false),
            last_error: AtomicU32::new(0),
            _pad: [0; 4],
        }
    }

    pub fn state(&self) -> CpuState {
        CpuState::from(self.state.load(Ordering::Acquire) as u8)
    }

    pub fn set_state(&self, state: CpuState) {
        self.state.store(state as u32, Ordering::Release);
    }

    pub fn is_online(&self) -> bool {
        self.state() == CpuState::Online
    }
}

#[derive(Debug)]
pub struct SmpStats {
    pub cpu_count: usize,
    pub cpus_online: usize,
    pub bsp_apic_id: u32,
    pub per_cpu: Vec<CpuStats>,
}

#[derive(Debug)]
pub struct CpuStats {
    pub cpu_id: u32,
    pub apic_id: u32,
    pub state: CpuState,
    pub idle_cycles: u64,
    pub total_cycles: u64,
    pub current_pid: u32,
}
