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
use super::super::error::{PciError, Result};
use super::super::types::PciAddress;
use super::access::{read8, read16, read32, write8, write16, write32};

pub struct ConfigSpace {
    address: PciAddress,
}

impl ConfigSpace {
    pub const fn new(address: PciAddress) -> Self {
        Self { address }
    }

    pub fn from_bdf(bus: u8, device: u8, function: u8) -> Self {
        Self::new(PciAddress::new(bus, device, function))
    }

    pub fn address(&self) -> PciAddress {
        self.address
    }

    pub fn read8(&self, offset: u16) -> Result<u8> {
        read8(self.address.bus, self.address.device, self.address.function, offset)
    }

    pub fn read16(&self, offset: u16) -> Result<u16> {
        read16(self.address.bus, self.address.device, self.address.function, offset)
    }

    pub fn read32(&self, offset: u16) -> Result<u32> {
        read32(self.address.bus, self.address.device, self.address.function, offset)
    }

    pub fn write8(&self, offset: u16, value: u8) -> Result<()> {
        write8(self.address.bus, self.address.device, self.address.function, offset, value)
    }

    pub fn write16(&self, offset: u16, value: u16) -> Result<()> {
        write16(self.address.bus, self.address.device, self.address.function, offset, value)
    }

    pub fn write32(&self, offset: u16, value: u32) -> Result<()> {
        write32(self.address.bus, self.address.device, self.address.function, offset, value)
    }

    pub fn vendor_id(&self) -> Result<u16> {
        self.read16(CFG_VENDOR_ID)
    }

    pub fn device_id(&self) -> Result<u16> {
        self.read16(CFG_DEVICE_ID)
    }

    pub fn command(&self) -> Result<u16> {
        self.read16(CFG_COMMAND)
    }

    pub fn set_command(&self, value: u16) -> Result<()> {
        self.write16(CFG_COMMAND, value)
    }

    pub fn status(&self) -> Result<u16> {
        self.read16(CFG_STATUS)
    }

    pub fn class_code(&self) -> Result<u8> {
        self.read8(CFG_CLASS_CODE)
    }

    pub fn subclass(&self) -> Result<u8> {
        self.read8(CFG_SUBCLASS)
    }

    pub fn prog_if(&self) -> Result<u8> {
        self.read8(CFG_PROG_IF)
    }

    pub fn revision_id(&self) -> Result<u8> {
        self.read8(CFG_REVISION_ID)
    }

    pub fn header_type(&self) -> Result<u8> {
        self.read8(CFG_HEADER_TYPE)
    }

    pub fn cache_line_size(&self) -> Result<u8> {
        self.read8(CFG_CACHE_LINE_SIZE)
    }

    pub fn set_cache_line_size(&self, size: u8) -> Result<()> {
        self.write8(CFG_CACHE_LINE_SIZE, size)
    }

    pub fn latency_timer(&self) -> Result<u8> {
        self.read8(CFG_LATENCY_TIMER)
    }

    pub fn set_latency_timer(&self, timer: u8) -> Result<()> {
        self.write8(CFG_LATENCY_TIMER, timer)
    }

    pub fn bar(&self, index: u8) -> Result<u32> {
        if index > 5 {
            return Err(PciError::InvalidBarIndex(index));
        }
        self.read32(bar_offset(index))
    }

    pub fn set_bar(&self, index: u8, value: u32) -> Result<()> {
        if index > 5 {
            return Err(PciError::InvalidBarIndex(index));
        }
        self.write32(bar_offset(index), value)
    }

    pub fn subsystem_vendor_id(&self) -> Result<u16> {
        self.read16(CFG_SUBSYSTEM_VENDOR_ID)
    }

    pub fn subsystem_id(&self) -> Result<u16> {
        self.read16(CFG_SUBSYSTEM_ID)
    }

    pub fn expansion_rom_base(&self) -> Result<u32> {
        self.read32(CFG_EXPANSION_ROM_BASE)
    }

    pub fn capabilities_pointer(&self) -> Result<u8> {
        self.read8(CFG_CAPABILITIES_PTR)
    }

    pub fn interrupt_line(&self) -> Result<u8> {
        self.read8(CFG_INTERRUPT_LINE)
    }

    pub fn set_interrupt_line(&self, line: u8) -> Result<()> {
        self.write8(CFG_INTERRUPT_LINE, line)
    }

    pub fn interrupt_pin(&self) -> Result<u8> {
        self.read8(CFG_INTERRUPT_PIN)
    }

    pub fn has_capabilities(&self) -> Result<bool> {
        let status = self.status()?;
        Ok((status & STS_CAPABILITIES_LIST) != 0)
    }

    pub fn is_multifunction(&self) -> Result<bool> {
        let header = self.header_type()?;
        Ok((header & HDR_TYPE_MULTIFUNCTION) != 0)
    }

    pub fn enable_bus_master(&self) -> Result<()> {
        let cmd = self.command()?;
        self.set_command(cmd | CMD_BUS_MASTER)
    }

    pub fn disable_bus_master(&self) -> Result<()> {
        let cmd = self.command()?;
        self.set_command(cmd & !CMD_BUS_MASTER)
    }

    pub fn is_bus_master_enabled(&self) -> Result<bool> {
        let cmd = self.command()?;
        Ok((cmd & CMD_BUS_MASTER) != 0)
    }

    pub fn enable_memory_space(&self) -> Result<()> {
        let cmd = self.command()?;
        self.set_command(cmd | CMD_MEMORY_SPACE)
    }

    pub fn disable_memory_space(&self) -> Result<()> {
        let cmd = self.command()?;
        self.set_command(cmd & !CMD_MEMORY_SPACE)
    }

    pub fn is_memory_space_enabled(&self) -> Result<bool> {
        let cmd = self.command()?;
        Ok((cmd & CMD_MEMORY_SPACE) != 0)
    }

    pub fn enable_io_space(&self) -> Result<()> {
        let cmd = self.command()?;
        self.set_command(cmd | CMD_IO_SPACE)
    }

    pub fn disable_io_space(&self) -> Result<()> {
        let cmd = self.command()?;
        self.set_command(cmd & !CMD_IO_SPACE)
    }

    pub fn is_io_space_enabled(&self) -> Result<bool> {
        let cmd = self.command()?;
        Ok((cmd & CMD_IO_SPACE) != 0)
    }

    pub fn disable_interrupts(&self) -> Result<()> {
        let cmd = self.command()?;
        self.set_command(cmd | CMD_INTERRUPT_DISABLE)
    }

    pub fn enable_interrupts(&self) -> Result<()> {
        let cmd = self.command()?;
        self.set_command(cmd & !CMD_INTERRUPT_DISABLE)
    }

    pub fn clear_error_bits(&self) -> Result<()> {
        let status = self.status()?;
        let error_bits = STS_DETECTED_PARITY_ERROR
            | STS_SIGNALED_SYSTEM_ERROR
            | STS_RECEIVED_MASTER_ABORT
            | STS_RECEIVED_TARGET_ABORT
            | STS_SIGNALED_TARGET_ABORT
            | STS_MASTER_DATA_PARITY_ERROR;
        self.write16(CFG_STATUS, status & error_bits)
    }
}
