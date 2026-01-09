// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::sync::atomic::{AtomicU64, Ordering};

use super::constants::*;
use super::error::{PciError, Result};
use super::types::PciAddress;

static CONFIG_READS: AtomicU64 = AtomicU64::new(0);
static CONFIG_WRITES: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
unsafe fn outl(port: u16, value: u32) {
    // SAFETY: caller ensures port access is valid
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nostack, preserves_flags));
}

#[inline(always)]
unsafe fn inl(port: u16) -> u32 {
    // SAFETY: caller ensures port access is valid
    let value: u32;
    core::arch::asm!("in eax, dx", in("dx") port, out("eax") value, options(nostack, preserves_flags));
    value
}

fn validate_access(bus: u8, device: u8, function: u8, offset: u16) -> Result<()> {
    if device > PCI_MAX_DEVICE {
        return Err(PciError::InvalidDevice(device));
    }
    if function > PCI_MAX_FUNCTION {
        return Err(PciError::InvalidFunction(function));
    }
    if offset >= PCI_CONFIG_SPACE_SIZE {
        return Err(PciError::InvalidOffset(offset));
    }
    Ok(())
}

fn validate_alignment(offset: u16, size: u8) -> Result<()> {
    if (offset & ((size as u16) - 1)) != 0 {
        return Err(PciError::UnalignedAccess { offset, alignment: size });
    }
    Ok(())
}

#[inline]
fn make_config_address(bus: u8, device: u8, function: u8, offset: u16) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

pub fn read8(bus: u8, device: u8, function: u8, offset: u16) -> Result<u8> {
    validate_access(bus, device, function, offset)?;
    CONFIG_READS.fetch_add(1, Ordering::Relaxed);

    let addr = make_config_address(bus, device, function, offset);
    let byte_offset = (offset & 3) as u16;

    // SAFETY: PCI config space ports are valid for kernel access
    let value = unsafe {
        outl(PCI_CONFIG_ADDRESS, addr);
        let data = inl(PCI_CONFIG_DATA);
        ((data >> (byte_offset * 8)) & 0xFF) as u8
    };

    Ok(value)
}

pub fn read16(bus: u8, device: u8, function: u8, offset: u16) -> Result<u16> {
    validate_access(bus, device, function, offset)?;
    validate_alignment(offset, 2)?;
    CONFIG_READS.fetch_add(1, Ordering::Relaxed);

    let addr = make_config_address(bus, device, function, offset);
    let word_offset = (offset & 2) as u16;

    // SAFETY: PCI config space ports are valid for kernel access
    let value = unsafe {
        outl(PCI_CONFIG_ADDRESS, addr);
        let data = inl(PCI_CONFIG_DATA);
        ((data >> (word_offset * 8)) & 0xFFFF) as u16
    };

    Ok(value)
}

pub fn read32(bus: u8, device: u8, function: u8, offset: u16) -> Result<u32> {
    validate_access(bus, device, function, offset)?;
    validate_alignment(offset, 4)?;
    CONFIG_READS.fetch_add(1, Ordering::Relaxed);

    let addr = make_config_address(bus, device, function, offset);

    // SAFETY: PCI config space ports are valid for kernel access
    let value = unsafe {
        outl(PCI_CONFIG_ADDRESS, addr);
        inl(PCI_CONFIG_DATA)
    };

    Ok(value)
}

pub fn write8(bus: u8, device: u8, function: u8, offset: u16, value: u8) -> Result<()> {
    validate_access(bus, device, function, offset)?;
    CONFIG_WRITES.fetch_add(1, Ordering::Relaxed);

    let addr = make_config_address(bus, device, function, offset);
    let byte_offset = (offset & 3) as u32;
    let mask = 0xFFu32 << (byte_offset * 8);

    // SAFETY: PCI config space ports are valid for kernel access
    unsafe {
        outl(PCI_CONFIG_ADDRESS, addr);
        let current = inl(PCI_CONFIG_DATA);
        let new_value = (current & !mask) | ((value as u32) << (byte_offset * 8));
        outl(PCI_CONFIG_DATA, new_value);
    }

    Ok(())
}

pub fn write16(bus: u8, device: u8, function: u8, offset: u16, value: u16) -> Result<()> {
    validate_access(bus, device, function, offset)?;
    validate_alignment(offset, 2)?;
    CONFIG_WRITES.fetch_add(1, Ordering::Relaxed);

    let addr = make_config_address(bus, device, function, offset);
    let word_offset = (offset & 2) as u32;
    let mask = 0xFFFFu32 << (word_offset * 8);

    // SAFETY: PCI config space ports are valid for kernel access
    unsafe {
        outl(PCI_CONFIG_ADDRESS, addr);
        let current = inl(PCI_CONFIG_DATA);
        let new_value = (current & !mask) | ((value as u32) << (word_offset * 8));
        outl(PCI_CONFIG_DATA, new_value);
    }

    Ok(())
}

pub fn write32(bus: u8, device: u8, function: u8, offset: u16, value: u32) -> Result<()> {
    validate_access(bus, device, function, offset)?;
    validate_alignment(offset, 4)?;
    CONFIG_WRITES.fetch_add(1, Ordering::Relaxed);

    let addr = make_config_address(bus, device, function, offset);

    // SAFETY: PCI config space ports are valid for kernel access
    unsafe {
        outl(PCI_CONFIG_ADDRESS, addr);
        outl(PCI_CONFIG_DATA, value);
    }

    Ok(())
}

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

#[inline]
pub fn read32_unchecked(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    CONFIG_READS.fetch_add(1, Ordering::Relaxed);
    let addr = pci_config_address(bus, device, function, offset);
    // SAFETY: PCI config space ports are valid for kernel access
    unsafe {
        outl(PCI_CONFIG_ADDRESS, addr);
        inl(PCI_CONFIG_DATA)
    }
}

#[inline]
pub fn write32_unchecked(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    CONFIG_WRITES.fetch_add(1, Ordering::Relaxed);
    let addr = pci_config_address(bus, device, function, offset);
    // SAFETY: PCI config space ports are valid for kernel access
    unsafe {
        outl(PCI_CONFIG_ADDRESS, addr);
        outl(PCI_CONFIG_DATA, value);
    }
}

pub fn get_config_stats() -> (u64, u64) {
    (
        CONFIG_READS.load(Ordering::Relaxed),
        CONFIG_WRITES.load(Ordering::Relaxed),
    )
}

pub fn reset_config_stats() {
    CONFIG_READS.store(0, Ordering::Relaxed);
    CONFIG_WRITES.store(0, Ordering::Relaxed);
}
