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

use super::super::config::ConfigSpace;
use super::super::constants::*;
use super::super::error::Result;
use super::super::types::PciCapability;
use super::enumerate::MAX_CAPABILITY_CHAIN;

pub struct CapabilityWalker<'a> {
    config: &'a ConfigSpace,
    current_offset: u8,
    iterations: usize,
}

impl<'a> CapabilityWalker<'a> {
    pub fn new(config: &'a ConfigSpace) -> Result<Option<Self>> {
        let status = config.status()?;
        if (status & STS_CAPABILITIES_LIST) == 0 {
            return Ok(None);
        }

        let ptr = config.capabilities_pointer()?;
        if ptr < 0x40 {
            return Ok(None);
        }

        Ok(Some(Self {
            config,
            current_offset: ptr,
            iterations: 0,
        }))
    }
}

impl<'a> Iterator for CapabilityWalker<'a> {
    type Item = Result<PciCapability>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_offset < 0x40
            || self.current_offset == 0xFF
            || self.iterations >= MAX_CAPABILITY_CHAIN
        {
            return None;
        }

        let header = match self.config.read32(self.current_offset as u16) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        let id = (header & 0xFF) as u8;
        let next = ((header >> 8) & 0xFF) as u8;

        let version = match id {
            CAP_ID_PM => ((header >> 16) & 0x07) as u8,
            CAP_ID_PCIE => ((header >> 16) & 0x0F) as u8,
            _ => 0,
        };

        let cap = PciCapability::with_version(id, self.current_offset, version);

        self.current_offset = if next == 0 || next == self.current_offset {
            0
        } else {
            next
        };
        self.iterations += 1;

        Some(Ok(cap))
    }
}
