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

pub mod calls;
pub mod error;
pub mod features;

pub use calls::{affinity_info, cpu_off, cpu_on, cpu_suspend, migrate_info_type};
pub use calls::{system_off, system_reset, system_reset2};
pub use error::PsciError;
pub use features::{features, psci_version, PsciVersion};

use core::arch::asm;

const PSCI_VERSION: u32 = 0x8400_0000;
const PSCI_CPU_SUSPEND_64: u32 = 0xC400_0001;
const PSCI_CPU_OFF: u32 = 0x8400_0002;
const PSCI_CPU_ON_64: u32 = 0xC400_0003;
const PSCI_AFFINITY_INFO_64: u32 = 0xC400_0004;
const PSCI_MIGRATE_64: u32 = 0xC400_0005;
const PSCI_MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
const PSCI_MIGRATE_INFO_UP_CPU_64: u32 = 0xC400_0007;
const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;
const PSCI_SYSTEM_RESET2_64: u32 = 0xC400_0012;
const PSCI_MEM_PROTECT: u32 = 0x8400_0013;
const PSCI_MEM_PROTECT_CHECK_RANGE_64: u32 = 0xC400_0014;
const PSCI_FEATURES: u32 = 0x8400_000A;
const PSCI_CPU_FREEZE: u32 = 0x8400_000B;
const PSCI_CPU_DEFAULT_SUSPEND_64: u32 = 0xC400_000C;
const PSCI_NODE_HW_STATE_64: u32 = 0xC400_000D;
const PSCI_SYSTEM_SUSPEND_64: u32 = 0xC400_000E;
const PSCI_SET_SUSPEND_MODE: u32 = 0x8400_000F;
const PSCI_STAT_RESIDENCY_64: u32 = 0xC400_0010;
const PSCI_STAT_COUNT_64: u32 = 0xC400_0011;

const PSCI_RET_SUCCESS: i32 = 0;
const PSCI_RET_NOT_SUPPORTED: i32 = -1;
const PSCI_RET_INVALID_PARAMS: i32 = -2;
const PSCI_RET_DENIED: i32 = -3;
const PSCI_RET_ALREADY_ON: i32 = -4;
const PSCI_RET_ON_PENDING: i32 = -5;
const PSCI_RET_INTERNAL_FAILURE: i32 = -6;
const PSCI_RET_NOT_PRESENT: i32 = -7;
const PSCI_RET_DISABLED: i32 = -8;
const PSCI_RET_INVALID_ADDRESS: i32 = -9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsciMethod {
    Hvc,
    Smc,
}

static mut PSCI_METHOD: PsciMethod = PsciMethod::Smc;

pub fn set_method(method: PsciMethod) {
    unsafe {
        PSCI_METHOD = method;
    }
}

pub fn psci_call(func: u32, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;

    unsafe {
        match PSCI_METHOD {
            PsciMethod::Smc => {
                asm!(
                    "smc #0",
                    inout("x0") func as u64 => ret,
                    in("x1") arg0,
                    in("x2") arg1,
                    in("x3") arg2,
                    options(nomem, nostack)
                );
            }
            PsciMethod::Hvc => {
                asm!(
                    "hvc #0",
                    inout("x0") func as u64 => ret,
                    in("x1") arg0,
                    in("x2") arg1,
                    in("x3") arg2,
                    options(nomem, nostack)
                );
            }
        }
    }

    ret
}

pub fn psci_call0(func: u32) -> i64 {
    psci_call(func, 0, 0, 0)
}

pub fn psci_call1(func: u32, arg0: u64) -> i64 {
    psci_call(func, arg0, 0, 0)
}

pub fn psci_call2(func: u32, arg0: u64, arg1: u64) -> i64 {
    psci_call(func, arg0, arg1, 0)
}
