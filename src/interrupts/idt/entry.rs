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

use x86_64::PrivilegeLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GateType {
    Interrupt = 0xE,
    Trap = 0xF,
}

#[derive(Debug, Clone, Copy)]
pub struct EntryOptions {
    pub gate_type: GateType,
    pub privilege_level: PrivilegeLevel,
    pub present: bool,
    pub ist_index: Option<u8>,
}

impl EntryOptions {
    pub const fn new() -> Self {
        Self {
            gate_type: GateType::Interrupt,
            privilege_level: PrivilegeLevel::Ring0,
            present: true,
            ist_index: None,
        }
    }

    pub const fn interrupt() -> Self {
        Self::new()
    }

    pub const fn trap() -> Self {
        Self {
            gate_type: GateType::Trap,
            privilege_level: PrivilegeLevel::Ring0,
            present: true,
            ist_index: None,
        }
    }

    pub const fn with_privilege_level(mut self, level: PrivilegeLevel) -> Self {
        self.privilege_level = level;
        self
    }

    pub const fn with_ist_index(mut self, index: u8) -> Self {
        self.ist_index = Some(index);
        self
    }

    pub const fn user_callable(mut self) -> Self {
        self.privilege_level = PrivilegeLevel::Ring3;
        self
    }
}

impl Default for EntryOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    InvalidIstIndex,
    HandlerNotPresent,
}

impl EntryError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidIstIndex => "IST index must be 0-6",
            Self::HandlerNotPresent => "Handler address is null",
        }
    }
}

pub fn validate_ist_index(index: u8) -> Result<(), EntryError> {
    if index > 6 {
        Err(EntryError::InvalidIstIndex)
    } else {
        Ok(())
    }
}

pub fn validate_handler_address(addr: u64) -> Result<(), EntryError> {
    if addr == 0 {
        Err(EntryError::HandlerNotPresent)
    } else {
        Ok(())
    }
}
