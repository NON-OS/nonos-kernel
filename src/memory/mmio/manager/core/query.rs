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

use super::super::super::error::{MmioError, MmioResult};
use super::super::super::types::MmioRegion;
use super::types::MmioManager;
use crate::memory::addr::VirtAddr;

impl MmioManager {
    pub fn find_region(&self, va: VirtAddr) -> Option<&MmioRegion> {
        self.regions.values().find(|r| r.contains(va))
    }

    pub fn validate_access(
        &self,
        va: VirtAddr,
        offset: usize,
        access_size: usize,
    ) -> MmioResult<&MmioRegion> {
        let region = self.find_region(va).ok_or(MmioError::InvalidBaseAddress)?;
        if !region.validate_access(offset, access_size) {
            return Err(MmioError::AccessOutOfBounds);
        }
        Ok(region)
    }

    pub fn regions(&self) -> impl Iterator<Item = &MmioRegion> {
        self.regions.values()
    }
}
