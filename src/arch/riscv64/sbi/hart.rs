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

use super::base::sbi_call;
use super::error::SbiError;

const EID_HSM: usize = 0x48534D;

const FID_HART_START: usize = 0;
const FID_HART_STOP: usize = 1;
const FID_HART_GET_STATUS: usize = 2;
const FID_HART_SUSPEND: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HartStatus {
    Started,
    Stopped,
    StartPending,
    StopPending,
    Suspended,
    SuspendPending,
    ResumePending,
    Unknown(usize),
}

impl From<usize> for HartStatus {
    fn from(status: usize) -> Self {
        match status {
            0 => Self::Started,
            1 => Self::Stopped,
            2 => Self::StartPending,
            3 => Self::StopPending,
            4 => Self::Suspended,
            5 => Self::SuspendPending,
            6 => Self::ResumePending,
            n => Self::Unknown(n),
        }
    }
}

pub fn hart_start(hartid: u64, start_addr: u64, opaque: u64) -> Result<(), SbiError> {
    let ret = sbi_call(
        EID_HSM,
        FID_HART_START,
        hartid as usize,
        start_addr as usize,
        opaque as usize,
    );

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(())
    }
}

pub fn hart_stop() -> Result<(), SbiError> {
    let ret = sbi_call(EID_HSM, FID_HART_STOP, 0, 0, 0);

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(())
    }
}

pub fn hart_get_status(hartid: u64) -> Result<HartStatus, SbiError> {
    let ret = sbi_call(EID_HSM, FID_HART_GET_STATUS, hartid as usize, 0, 0);

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(HartStatus::from(ret.value))
    }
}

pub fn hart_suspend(suspend_type: u32, resume_addr: u64, opaque: u64) -> Result<(), SbiError> {
    let ret = sbi_call(
        EID_HSM,
        FID_HART_SUSPEND,
        suspend_type as usize,
        resume_addr as usize,
        opaque as usize,
    );

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(())
    }
}

pub const SUSPEND_DEFAULT_RETENTIVE: u32 = 0x0000_0000;
pub const SUSPEND_DEFAULT_NON_RETENTIVE: u32 = 0x8000_0000;

pub fn suspend_retentive() -> Result<(), SbiError> {
    hart_suspend(SUSPEND_DEFAULT_RETENTIVE, 0, 0)
}

pub fn suspend_non_retentive(resume_addr: u64, opaque: u64) -> Result<(), SbiError> {
    hart_suspend(SUSPEND_DEFAULT_NON_RETENTIVE, resume_addr, opaque)
}
