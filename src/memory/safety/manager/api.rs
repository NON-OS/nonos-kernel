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

use super::super::error::SafetyResult;
use super::super::types::{AccessType, ProtectionLevel};
use super::state::MEMORY_SAFETY;

pub fn init() -> Result<(), &'static str> {
    MEMORY_SAFETY.initialize()
}

pub fn set_protection_level(level: ProtectionLevel) -> Result<(), &'static str> {
    if !MEMORY_SAFETY.is_initialized() {
        return Err("Memory safety not initialized");
    }
    *MEMORY_SAFETY.protection_level.write() = level;
    Ok(())
}

pub fn validate_read(addr: u64, size: usize) -> SafetyResult<()> {
    MEMORY_SAFETY.validate_access(addr, size, AccessType::Read)
}

pub fn validate_write(addr: u64, size: usize) -> SafetyResult<()> {
    MEMORY_SAFETY.validate_access(addr, size, AccessType::Write)
}

pub fn validate_execute(addr: u64, size: usize) -> SafetyResult<()> {
    MEMORY_SAFETY.validate_access(addr, size, AccessType::Execute)
}
