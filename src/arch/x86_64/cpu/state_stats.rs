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

use super::cpuid::cpuid_calls;
use super::frequency::{get_core_frequency, get_tsc_frequency};
use super::msr::{msr_reads, msr_writes};
use super::state_globals::{CPU_COUNT, INITIALIZED};
use core::sync::atomic::Ordering;

#[derive(Debug, Clone, Copy, Default)]
pub struct CpuStats {
    pub cpuid_calls: u64,
    pub msr_reads: u64,
    pub msr_writes: u64,
    pub tsc_frequency: u64,
    pub core_frequency: u64,
    pub cpu_count: u32,
    pub initialized: bool,
}

pub fn get_stats() -> CpuStats {
    CpuStats {
        cpuid_calls: cpuid_calls(),
        msr_reads: msr_reads(),
        msr_writes: msr_writes(),
        tsc_frequency: get_tsc_frequency(),
        core_frequency: get_core_frequency(),
        cpu_count: CPU_COUNT.load(Ordering::Relaxed),
        initialized: INITIALIZED.load(Ordering::Relaxed),
    }
}
