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

use super::super::error::NvmeError;
use super::super::namespace::Namespace;

pub struct LbaValidator;

impl LbaValidator {
    pub fn validate(ns: &Namespace, start_lba: u64, block_count: u16) -> Result<(), NvmeError> {
        if block_count == 0 {
            return Err(NvmeError::InvalidBlockCount);
        }
        let end_lba =
            start_lba.checked_add(block_count as u64).ok_or(NvmeError::LbaRangeOverflow)?;
        if end_lba > ns.block_count() {
            return Err(NvmeError::LbaExceedsCapacity);
        }
        Ok(())
    }

    pub fn validate_range(
        capacity: u64,
        start_lba: u64,
        block_count: u16,
    ) -> Result<(), NvmeError> {
        if block_count == 0 {
            return Err(NvmeError::InvalidBlockCount);
        }
        let end_lba =
            start_lba.checked_add(block_count as u64).ok_or(NvmeError::LbaRangeOverflow)?;
        if end_lba > capacity {
            return Err(NvmeError::LbaExceedsCapacity);
        }
        Ok(())
    }
}
