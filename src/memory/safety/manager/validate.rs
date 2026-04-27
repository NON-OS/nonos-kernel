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

use super::super::constants::ACCESS_HISTORY_MAX;
use super::super::error::{MemoryError, SafetyResult};
use super::super::types::*;
use super::helpers::get_timestamp;
use super::state::MemorySafety;
use crate::memory::layout;

impl MemorySafety {
    pub(super) fn validate_access(
        &self,
        addr: u64,
        size: usize,
        access_type: AccessType,
    ) -> SafetyResult<()> {
        if !self.is_initialized() {
            return Err(MemoryError::NotInitialized);
        }
        if addr == 0 {
            return Err(MemoryError::NullPointer);
        }

        let _end_addr = addr.checked_add(size as u64).ok_or(MemoryError::AddressOverflow)?;
        if size >= layout::PAGE_SIZE && addr % layout::PAGE_SIZE as u64 != 0 {
            return Err(MemoryError::BadAlignment);
        }

        let regions = self.regions.read();
        let region = regions
            .iter()
            .find(|r| r.contains_range(addr, size as u64))
            .ok_or(MemoryError::UnmappedAccess)?;

        match access_type {
            AccessType::Read if !region.read_allowed => return Err(MemoryError::ReadViolation),
            AccessType::Write if !region.write_allowed => return Err(MemoryError::WriteViolation),
            AccessType::Execute if !region.execute_allowed => {
                return Err(MemoryError::ExecuteViolation)
            }
            _ => {}
        }

        self.record_access(addr, size, access_type);
        if region.protection >= ProtectionLevel::Paranoid {
            self.check_corruption(addr, size)?;
        }
        Ok(())
    }

    pub(super) fn record_access(&self, addr: u64, size: usize, access_type: AccessType) {
        let timestamp = get_timestamp();
        let pattern = AccessPattern { addr, size, timestamp, access_type };
        let mut history = self.access_history.write();
        history.push(pattern);
        if history.len() > ACCESS_HISTORY_MAX {
            history.remove(0);
        }
    }
}
