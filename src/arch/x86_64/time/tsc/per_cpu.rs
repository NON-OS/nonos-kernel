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

use super::constants::MAX_CPUS;
use super::error::{TscError, TscResult};
use super::asm::rdtsc;
use super::state::{CALIBRATION, PER_CPU_TSC};

pub fn init_cpu(cpu_id: u32) -> TscResult<()> {
    if cpu_id as usize >= MAX_CPUS {
        return Err(TscError::PerCpuNotInit);
    }

    let current_tsc = rdtsc();

    let mut per_cpu = PER_CPU_TSC.write();
    let cpu_state = &mut per_cpu[cpu_id as usize];

    if cpu_id == 0 {
        cpu_state.offset = 0;
    } else {
        let boot_tsc = CALIBRATION.read().boot_tsc;
        cpu_state.offset = current_tsc as i64 - boot_tsc as i64;
    }

    cpu_state.initialized = true;
    cpu_state.last_sync_tsc = current_tsc;
    cpu_state.sync_error = 0;

    Ok(())
}

pub fn sync_with_bsp(cpu_id: u32) -> TscResult<()> {
    if cpu_id as usize >= MAX_CPUS {
        return Err(TscError::PerCpuNotInit);
    }

    if cpu_id == 0 {
        return Ok(());
    }

    let current_tsc = rdtsc();
    let boot_tsc = CALIBRATION.read().boot_tsc;

    let mut per_cpu = PER_CPU_TSC.write();
    let cpu_state = &mut per_cpu[cpu_id as usize];

    cpu_state.offset = current_tsc as i64 - boot_tsc as i64;
    cpu_state.last_sync_tsc = current_tsc;

    Ok(())
}

pub fn get_cpu_offset(cpu_id: u32) -> Option<i64> {
    if cpu_id as usize >= MAX_CPUS {
        return None;
    }

    let per_cpu = PER_CPU_TSC.read();
    let cpu_state = &per_cpu[cpu_id as usize];

    if cpu_state.initialized {
        Some(cpu_state.offset)
    } else {
        None
    }
}

pub fn read_synchronized(cpu_id: u32) -> u64 {
    let raw = rdtsc();

    if cpu_id as usize >= MAX_CPUS {
        return raw;
    }

    let per_cpu = PER_CPU_TSC.read();
    let cpu_state = &per_cpu[cpu_id as usize];

    if cpu_state.initialized {
        if cpu_state.offset >= 0 {
            raw.saturating_sub(cpu_state.offset as u64)
        } else {
            raw.saturating_add((-cpu_state.offset) as u64)
        }
    } else {
        raw
    }
}
