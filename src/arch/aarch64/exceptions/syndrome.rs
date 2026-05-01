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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionClass {
    Unknown,
    WfeWfi,
    Cp15Mcr,
    Cp15Mcrr,
    Cp14Mcr,
    Cp14Ldc,
    FpAccess,
    Cp14Mrrc,
    BranchTarget,
    IllegalState,
    Svc32,
    Svc64,
    Hvc64,
    Smc64,
    SysReg,
    SveAccess,
    EretEretaa,
    Pac,
    InstructionAbortLower,
    InstructionAbortSame,
    PcAlignment,
    DataAbortLower,
    DataAbortSame,
    SpAlignment,
    Fp32,
    Fp64,
    SError,
    BreakpointLower,
    BreakpointSame,
    SoftwareStepLower,
    SoftwareStepSame,
    WatchpointLower,
    WatchpointSame,
    Bkpt32,
    Brk64,
}

impl From<u8> for ExceptionClass {
    fn from(ec: u8) -> Self {
        match ec {
            0b000000 => Self::Unknown,
            0b000001 => Self::WfeWfi,
            0b000011 => Self::Cp15Mcr,
            0b000100 => Self::Cp15Mcrr,
            0b000101 => Self::Cp14Mcr,
            0b000110 => Self::Cp14Ldc,
            0b000111 => Self::FpAccess,
            0b001100 => Self::Cp14Mrrc,
            0b001101 => Self::BranchTarget,
            0b001110 => Self::IllegalState,
            0b010001 => Self::Svc32,
            0b010101 => Self::Svc64,
            0b010110 => Self::Hvc64,
            0b010111 => Self::Smc64,
            0b011000 => Self::SysReg,
            0b011001 => Self::SveAccess,
            0b011010 => Self::EretEretaa,
            0b011100 => Self::Pac,
            0b100000 => Self::InstructionAbortLower,
            0b100001 => Self::InstructionAbortSame,
            0b100010 => Self::PcAlignment,
            0b100100 => Self::DataAbortLower,
            0b100101 => Self::DataAbortSame,
            0b100110 => Self::SpAlignment,
            0b101000 => Self::Fp32,
            0b101100 => Self::Fp64,
            0b101111 => Self::SError,
            0b110000 => Self::BreakpointLower,
            0b110001 => Self::BreakpointSame,
            0b110010 => Self::SoftwareStepLower,
            0b110011 => Self::SoftwareStepSame,
            0b110100 => Self::WatchpointLower,
            0b110101 => Self::WatchpointSame,
            0b111000 => Self::Bkpt32,
            0b111100 => Self::Brk64,
            _ => Self::Unknown,
        }
    }
}

impl ExceptionClass {
    pub fn is_data_abort(&self) -> bool {
        matches!(self, Self::DataAbortLower | Self::DataAbortSame)
    }

    pub fn is_instruction_abort(&self) -> bool {
        matches!(self, Self::InstructionAbortLower | Self::InstructionAbortSame)
    }

    pub fn is_alignment(&self) -> bool {
        matches!(self, Self::PcAlignment | Self::SpAlignment)
    }

    pub fn is_syscall(&self) -> bool {
        matches!(self, Self::Svc32 | Self::Svc64)
    }

    pub fn is_debug(&self) -> bool {
        matches!(
            self,
            Self::BreakpointLower
                | Self::BreakpointSame
                | Self::SoftwareStepLower
                | Self::SoftwareStepSame
                | Self::WatchpointLower
                | Self::WatchpointSame
                | Self::Bkpt32
                | Self::Brk64
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EsrDecoded {
    pub class: ExceptionClass,
    pub il: bool,
    pub iss: u32,
}

pub fn decode_esr(esr: u64) -> EsrDecoded {
    let ec = ((esr >> 26) & 0x3F) as u8;
    let il = (esr & (1 << 25)) != 0;
    let iss = (esr & 0x01FF_FFFF) as u32;

    EsrDecoded {
        class: ExceptionClass::from(ec),
        il,
        iss,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DataAbortInfo {
    pub wnr: bool,
    pub dfsc: u8,
    pub cm: bool,
    pub s1ptw: bool,
    pub isv: bool,
    pub sas: u8,
    pub sse: bool,
    pub srt: u8,
    pub sf: bool,
    pub ar: bool,
}

pub fn decode_data_abort(iss: u32) -> DataAbortInfo {
    DataAbortInfo {
        wnr: (iss & (1 << 6)) != 0,
        dfsc: (iss & 0x3F) as u8,
        cm: (iss & (1 << 8)) != 0,
        s1ptw: (iss & (1 << 7)) != 0,
        isv: (iss & (1 << 24)) != 0,
        sas: ((iss >> 22) & 0x3) as u8,
        sse: (iss & (1 << 21)) != 0,
        srt: ((iss >> 16) & 0x1F) as u8,
        sf: (iss & (1 << 15)) != 0,
        ar: (iss & (1 << 14)) != 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultStatusCode {
    AddressSizeFaultL0,
    AddressSizeFaultL1,
    AddressSizeFaultL2,
    AddressSizeFaultL3,
    TranslationFaultL0,
    TranslationFaultL1,
    TranslationFaultL2,
    TranslationFaultL3,
    AccessFlagFaultL1,
    AccessFlagFaultL2,
    AccessFlagFaultL3,
    PermissionFaultL1,
    PermissionFaultL2,
    PermissionFaultL3,
    SynchronousExternalAbort,
    SynchronousTagCheckFail,
    AlignmentFault,
    TlbConflict,
    Unknown,
}

impl From<u8> for FaultStatusCode {
    fn from(dfsc: u8) -> Self {
        match dfsc {
            0b000000 => Self::AddressSizeFaultL0,
            0b000001 => Self::AddressSizeFaultL1,
            0b000010 => Self::AddressSizeFaultL2,
            0b000011 => Self::AddressSizeFaultL3,
            0b000100 => Self::TranslationFaultL0,
            0b000101 => Self::TranslationFaultL1,
            0b000110 => Self::TranslationFaultL2,
            0b000111 => Self::TranslationFaultL3,
            0b001001 => Self::AccessFlagFaultL1,
            0b001010 => Self::AccessFlagFaultL2,
            0b001011 => Self::AccessFlagFaultL3,
            0b001101 => Self::PermissionFaultL1,
            0b001110 => Self::PermissionFaultL2,
            0b001111 => Self::PermissionFaultL3,
            0b010000 => Self::SynchronousExternalAbort,
            0b010001 => Self::SynchronousTagCheckFail,
            0b100001 => Self::AlignmentFault,
            0b110000 => Self::TlbConflict,
            _ => Self::Unknown,
        }
    }
}
