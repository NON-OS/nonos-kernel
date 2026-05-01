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

use super::{psci_call, psci_call0, psci_call1, psci_call2};
use super::error::PsciError;

const PSCI_CPU_SUSPEND_64: u32 = 0xC400_0001;
const PSCI_CPU_OFF: u32 = 0x8400_0002;
const PSCI_CPU_ON_64: u32 = 0xC400_0003;
const PSCI_AFFINITY_INFO_64: u32 = 0xC400_0004;
const PSCI_MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;
const PSCI_SYSTEM_RESET2_64: u32 = 0xC400_0012;
const PSCI_SYSTEM_SUSPEND_64: u32 = 0xC400_000E;
const PSCI_CPU_DEFAULT_SUSPEND_64: u32 = 0xC400_000C;
const PSCI_NODE_HW_STATE_64: u32 = 0xC400_000D;

pub fn cpu_on(target_cpu: u64, entry_point: u64, context_id: u64) -> Result<(), PsciError> {
    let ret = psci_call(PSCI_CPU_ON_64, target_cpu, entry_point, context_id);
    PsciError::from_ret(ret as i32)
}

pub fn cpu_off() -> Result<(), PsciError> {
    let ret = psci_call0(PSCI_CPU_OFF);
    PsciError::from_ret(ret as i32)
}

pub fn cpu_suspend(power_state: u64, entry_point: u64, context_id: u64) -> Result<(), PsciError> {
    let ret = psci_call(PSCI_CPU_SUSPEND_64, power_state, entry_point, context_id);
    PsciError::from_ret(ret as i32)
}

pub fn affinity_info(target_affinity: u64, lowest_affinity_level: u64) -> Result<AffinityState, PsciError> {
    let ret = psci_call2(PSCI_AFFINITY_INFO_64, target_affinity, lowest_affinity_level);

    if ret < 0 {
        PsciError::from_ret(ret as i32)?;
    }

    match ret {
        0 => Ok(AffinityState::On),
        1 => Ok(AffinityState::Off),
        2 => Ok(AffinityState::OnPending),
        _ => Err(PsciError::InvalidParams),
    }
}

pub fn migrate_info_type() -> Result<MigrateType, PsciError> {
    let ret = psci_call0(PSCI_MIGRATE_INFO_TYPE);

    if ret < 0 {
        PsciError::from_ret(ret as i32)?;
    }

    match ret {
        0 => Ok(MigrateType::SingleCore),
        1 => Ok(MigrateType::SingleCoreNotUp),
        2 => Ok(MigrateType::NotRequired),
        _ => Err(PsciError::InvalidParams),
    }
}

pub fn system_off() -> ! {
    psci_call0(PSCI_SYSTEM_OFF);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

pub fn system_reset() -> ! {
    psci_call0(PSCI_SYSTEM_RESET);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

pub fn system_reset2(reset_type: u32, cookie: u64) -> ! {
    psci_call2(PSCI_SYSTEM_RESET2_64, reset_type as u64, cookie);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

pub fn system_suspend(entry_point: u64, context_id: u64) -> Result<(), PsciError> {
    let ret = psci_call2(PSCI_SYSTEM_SUSPEND_64, entry_point, context_id);
    PsciError::from_ret(ret as i32)
}

pub fn cpu_default_suspend(entry_point: u64, context_id: u64) -> Result<(), PsciError> {
    let ret = psci_call2(PSCI_CPU_DEFAULT_SUSPEND_64, entry_point, context_id);
    PsciError::from_ret(ret as i32)
}

pub fn node_hw_state(target_cpu: u64, power_level: u64) -> Result<HwState, PsciError> {
    let ret = psci_call2(PSCI_NODE_HW_STATE_64, target_cpu, power_level);

    if ret < 0 {
        PsciError::from_ret(ret as i32)?;
    }

    match ret {
        0 => Ok(HwState::On),
        1 => Ok(HwState::Off),
        2 => Ok(HwState::Standby),
        _ => Err(PsciError::InvalidParams),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityState {
    On,
    Off,
    OnPending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrateType {
    SingleCore,
    SingleCoreNotUp,
    NotRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwState {
    On,
    Off,
    Standby,
}
