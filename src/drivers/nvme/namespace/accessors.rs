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
use super::super::types::LbaFormat;
use super::types::Namespace;

impl Namespace {
    #[inline]
    pub const fn nsid(&self) -> u32 {
        self.nsid
    }
    #[inline]
    pub const fn size_bytes(&self) -> u64 {
        self.size_blocks * (self.block_size as u64)
    }
    #[inline]
    pub const fn capacity_bytes(&self) -> u64 {
        self.capacity_blocks * (self.block_size as u64)
    }
    #[inline]
    pub const fn block_size(&self) -> u32 {
        self.block_size
    }
    #[inline]
    pub const fn block_count(&self) -> u64 {
        self.size_blocks
    }

    pub fn validate_lba_range(&self, start_lba: u64, block_count: u16) -> Result<(), NvmeError> {
        if block_count == 0 {
            return Err(NvmeError::InvalidBlockCount);
        }
        let end_lba =
            start_lba.checked_add(block_count as u64).ok_or(NvmeError::LbaRangeOverflow)?;
        if end_lba > self.size_blocks {
            return Err(NvmeError::LbaExceedsCapacity);
        }
        Ok(())
    }

    pub fn blocks_to_bytes(&self, blocks: u64) -> u64 {
        blocks << self.block_size_shift
    }
    pub fn bytes_to_blocks(&self, bytes: u64) -> u64 {
        bytes >> self.block_size_shift
    }
    pub fn bytes_to_blocks_ceil(&self, bytes: u64) -> u64 {
        let mask = (1u64 << self.block_size_shift) - 1;
        (bytes + mask) >> self.block_size_shift
    }
    pub fn active_lba_format(&self) -> Option<&LbaFormat> {
        self.lba_formats.get(self.active_lba_format_index as usize)
    }
    pub fn supports_thin_provisioning(&self) -> bool {
        self.features.thin_provisioning
    }
    pub fn is_shared(&self) -> bool {
        self.multi_path.shared_namespace
    }
    pub fn has_data_protection(&self) -> bool {
        self.protection.enabled_type != 0
    }
    pub fn size_gb(&self) -> f64 {
        (self.size_bytes() as f64) / (1024.0 * 1024.0 * 1024.0)
    }
}
