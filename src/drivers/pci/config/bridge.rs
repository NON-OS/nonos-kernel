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

use super::super::constants::*;
use super::super::error::Result;
use super::super::types::PciAddress;
use super::config_space::ConfigSpace;

pub struct BridgeConfigSpace {
    config: ConfigSpace,
}

impl BridgeConfigSpace {
    pub fn new(address: PciAddress) -> Self {
        Self {
            config: ConfigSpace::new(address),
        }
    }

    pub fn config(&self) -> &ConfigSpace {
        &self.config
    }

    pub fn primary_bus(&self) -> Result<u8> {
        self.config.read8(CFG_PRIMARY_BUS)
    }

    pub fn set_primary_bus(&self, bus: u8) -> Result<()> {
        self.config.write8(CFG_PRIMARY_BUS, bus)
    }

    pub fn secondary_bus(&self) -> Result<u8> {
        self.config.read8(CFG_SECONDARY_BUS)
    }

    pub fn set_secondary_bus(&self, bus: u8) -> Result<()> {
        self.config.write8(CFG_SECONDARY_BUS, bus)
    }

    pub fn subordinate_bus(&self) -> Result<u8> {
        self.config.read8(CFG_SUBORDINATE_BUS)
    }

    pub fn set_subordinate_bus(&self, bus: u8) -> Result<()> {
        self.config.write8(CFG_SUBORDINATE_BUS, bus)
    }

    pub fn secondary_latency_timer(&self) -> Result<u8> {
        self.config.read8(CFG_SECONDARY_LATENCY)
    }

    pub fn io_base(&self) -> Result<u8> {
        self.config.read8(CFG_IO_BASE)
    }

    pub fn io_limit(&self) -> Result<u8> {
        self.config.read8(CFG_IO_LIMIT)
    }

    pub fn secondary_status(&self) -> Result<u16> {
        self.config.read16(CFG_SECONDARY_STATUS)
    }

    pub fn memory_base(&self) -> Result<u16> {
        self.config.read16(CFG_MEMORY_BASE)
    }

    pub fn memory_limit(&self) -> Result<u16> {
        self.config.read16(CFG_MEMORY_LIMIT)
    }

    pub fn prefetch_memory_base(&self) -> Result<u16> {
        self.config.read16(CFG_PREFETCH_MEMORY_BASE)
    }

    pub fn prefetch_memory_limit(&self) -> Result<u16> {
        self.config.read16(CFG_PREFETCH_MEMORY_LIMIT)
    }

    pub fn prefetch_base_upper(&self) -> Result<u32> {
        self.config.read32(CFG_PREFETCH_BASE_UPPER)
    }

    pub fn prefetch_limit_upper(&self) -> Result<u32> {
        self.config.read32(CFG_PREFETCH_LIMIT_UPPER)
    }

    pub fn bridge_control(&self) -> Result<u16> {
        self.config.read16(CFG_BRIDGE_CONTROL)
    }

    pub fn set_bridge_control(&self, value: u16) -> Result<()> {
        self.config.write16(CFG_BRIDGE_CONTROL, value)
    }

    pub fn reset_secondary_bus(&self) -> Result<()> {
        let ctrl = self.bridge_control()?;
        self.set_bridge_control(ctrl | BRIDGE_CTL_SECONDARY_BUS_RESET)?;

        for _ in 0..1000 {
            core::hint::spin_loop();
        }

        self.set_bridge_control(ctrl & !BRIDGE_CTL_SECONDARY_BUS_RESET)
    }

    pub fn io_window(&self) -> Result<(u32, u32)> {
        let base_low = self.io_base()? as u32;
        let limit_low = self.io_limit()? as u32;

        let base = (base_low & 0xF0) << 8;
        let limit = ((limit_low & 0xF0) << 8) | 0xFFF;

        if (base_low & 0x0F) == 0x01 {
            let base_high = self.config.read16(CFG_IO_BASE_UPPER)? as u32;
            let limit_high = self.config.read16(CFG_IO_LIMIT_UPPER)? as u32;
            Ok((base | (base_high << 16), limit | (limit_high << 16)))
        } else {
            Ok((base, limit))
        }
    }

    pub fn memory_window(&self) -> Result<(u32, u32)> {
        let base = (self.memory_base()? as u32 & 0xFFF0) << 16;
        let limit = ((self.memory_limit()? as u32 & 0xFFF0) << 16) | 0xFFFFF;
        Ok((base, limit))
    }

    pub fn prefetch_window(&self) -> Result<(u64, u64)> {
        let base_low = (self.prefetch_memory_base()? as u64 & 0xFFF0) << 16;
        let limit_low = ((self.prefetch_memory_limit()? as u64 & 0xFFF0) << 16) | 0xFFFFF;

        let base_type = self.prefetch_memory_base()? & 0x0F;
        if base_type == 0x01 {
            let base_high = self.prefetch_base_upper()? as u64;
            let limit_high = self.prefetch_limit_upper()? as u64;
            Ok((base_low | (base_high << 32), limit_low | (limit_high << 32)))
        } else {
            Ok((base_low, limit_low))
        }
    }
}
