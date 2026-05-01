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
pub enum TrapCause {
    Exception(ExceptionCode),
    Interrupt(InterruptCode),
}

impl TrapCause {
    pub fn from_scause(scause: usize) -> Self {
        let is_interrupt = (scause >> 63) != 0;
        let code = scause & ((1 << 63) - 1);

        if is_interrupt {
            TrapCause::Interrupt(InterruptCode::from(code))
        } else {
            TrapCause::Exception(ExceptionCode::from(code))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionCode {
    InstructionMisaligned,
    InstructionAccessFault,
    IllegalInstruction,
    Breakpoint,
    LoadMisaligned,
    LoadAccessFault,
    StoreMisaligned,
    StoreAccessFault,
    UserEcall,
    SupervisorEcall,
    MachineEcall,
    InstructionPageFault,
    LoadPageFault,
    StorePageFault,
    Unknown(usize),
}

impl From<usize> for ExceptionCode {
    fn from(code: usize) -> Self {
        match code {
            0 => Self::InstructionMisaligned,
            1 => Self::InstructionAccessFault,
            2 => Self::IllegalInstruction,
            3 => Self::Breakpoint,
            4 => Self::LoadMisaligned,
            5 => Self::LoadAccessFault,
            6 => Self::StoreMisaligned,
            7 => Self::StoreAccessFault,
            8 => Self::UserEcall,
            9 => Self::SupervisorEcall,
            11 => Self::MachineEcall,
            12 => Self::InstructionPageFault,
            13 => Self::LoadPageFault,
            15 => Self::StorePageFault,
            n => Self::Unknown(n),
        }
    }
}

impl ExceptionCode {
    pub fn is_page_fault(&self) -> bool {
        matches!(
            self,
            Self::InstructionPageFault | Self::LoadPageFault | Self::StorePageFault
        )
    }

    pub fn is_syscall(&self) -> bool {
        matches!(
            self,
            Self::UserEcall | Self::SupervisorEcall | Self::MachineEcall
        )
    }

    pub fn is_access_fault(&self) -> bool {
        matches!(
            self,
            Self::InstructionAccessFault | Self::LoadAccessFault | Self::StoreAccessFault
        )
    }

    pub fn is_misaligned(&self) -> bool {
        matches!(
            self,
            Self::InstructionMisaligned | Self::LoadMisaligned | Self::StoreMisaligned
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptCode {
    UserSoftware,
    SupervisorSoftware,
    MachineSoftware,
    UserTimer,
    SupervisorTimer,
    MachineTimer,
    UserExternal,
    SupervisorExternal,
    MachineExternal,
    Unknown(usize),
}

impl From<usize> for InterruptCode {
    fn from(code: usize) -> Self {
        match code {
            0 => Self::UserSoftware,
            1 => Self::SupervisorSoftware,
            3 => Self::MachineSoftware,
            4 => Self::UserTimer,
            5 => Self::SupervisorTimer,
            7 => Self::MachineTimer,
            8 => Self::UserExternal,
            9 => Self::SupervisorExternal,
            11 => Self::MachineExternal,
            n => Self::Unknown(n),
        }
    }
}

impl InterruptCode {
    pub fn is_timer(&self) -> bool {
        matches!(
            self,
            Self::UserTimer | Self::SupervisorTimer | Self::MachineTimer
        )
    }

    pub fn is_software(&self) -> bool {
        matches!(
            self,
            Self::UserSoftware | Self::SupervisorSoftware | Self::MachineSoftware
        )
    }

    pub fn is_external(&self) -> bool {
        matches!(
            self,
            Self::UserExternal | Self::SupervisorExternal | Self::MachineExternal
        )
    }
}
