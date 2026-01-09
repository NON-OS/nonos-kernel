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

use x86_64::PhysAddr;

use super::config::{read32_unchecked, write32_unchecked};
use super::constants::*;
use super::error::{BarType, PciError, ProtectedRegion, Result};
use super::types::PciBar;

fn validate_mmio_address(address: u64, size: u64) -> Result<()> {
    if address == 0 {
        return Err(PciError::InvalidBarAddress(0));
    }

    if address < MIN_MMIO_ADDRESS {
        return Err(PciError::BarOverlapsProtected {
            address,
            region: ProtectedRegion::LegacyBios,
        });
    }

    if address > MAX_PHYSICAL_ADDRESS {
        return Err(PciError::InvalidBarAddress(address));
    }

    let end = address.saturating_add(size);
    if end > MAX_PHYSICAL_ADDRESS {
        return Err(PciError::InvalidBarAddress(address));
    }

    if size > MAX_BAR_SIZE {
        return Err(PciError::BarTooLarge { size, max: MAX_BAR_SIZE });
    }

    if is_protected_region(address, size) {
        let region = identify_protected_region(address);
        return Err(PciError::BarOverlapsProtected { address, region });
    }

    Ok(())
}

fn is_protected_region(address: u64, size: u64) -> bool {
    let end = address.saturating_add(size);

    if address < 0x100000 {
        return true;
    }

    let apic_base = 0xFEE0_0000u64;
    let apic_end = 0xFEE0_1000u64;
    if address < apic_end && end > apic_base {
        return true;
    }

    let ioapic_base = 0xFEC0_0000u64;
    let ioapic_end = 0xFED0_0000u64;
    if address < ioapic_end && end > ioapic_base {
        return true;
    }

    if address >= 0xFFFF_8000_0000_0000 {
        return true;
    }

    false
}

fn identify_protected_region(address: u64) -> ProtectedRegion {
    if address < 0x100000 {
        return ProtectedRegion::LegacyBios;
    }

    let apic_base = 0xFEE0_0000u64;
    let apic_end = 0xFEE0_1000u64;
    if address >= apic_base && address < apic_end {
        return ProtectedRegion::LocalApicMmio;
    }

    let ioapic_base = 0xFEC0_0000u64;
    let ioapic_end = 0xFED0_0000u64;
    if address >= ioapic_base && address < ioapic_end {
        return ProtectedRegion::IoapicMmio;
    }

    if address >= 0xFFFF_8000_0000_0000 {
        return ProtectedRegion::KernelCode;
    }

    ProtectedRegion::ReservedMemory
}

fn validate_io_port(port: u16, size: u32) -> Result<()> {
    if port == 0 {
        return Err(PciError::InvalidBarAddress(0));
    }

    let end = (port as u32).saturating_add(size);
    if end > 0x10000 {
        return Err(PciError::InvalidBarAddress(port as u64));
    }

    if port < 0x100 && port != 0 {
        return Err(PciError::BarOverlapsProtected {
            address: port as u64,
            region: ProtectedRegion::LegacyBios,
        });
    }

    Ok(())
}

pub fn decode_bar(bus: u8, device: u8, function: u8, index: u8) -> Result<PciBar> {
    if index > 5 {
        return Err(PciError::InvalidBarIndex(index));
    }

    let offset = (CFG_BAR0 + (index as u16 * 4)) as u8;
    let original = read32_unchecked(bus, device, function, offset);

    if original == 0 || original == 0xFFFF_FFFF {
        return Ok(PciBar::NotPresent);
    }

    write32_unchecked(bus, device, function, offset, 0xFFFF_FFFF);
    let size_mask = read32_unchecked(bus, device, function, offset);
    write32_unchecked(bus, device, function, offset, original);

    if size_mask == 0 || size_mask == 0xFFFF_FFFF {
        return Ok(PciBar::NotPresent);
    }

    if (original & BAR_TYPE_MASK) == BAR_TYPE_IO {
        let port = (original & BAR_IO_ADDR_MASK) as u16;
        let size_bits = size_mask & BAR_IO_ADDR_MASK;
        let size = (!size_bits).wrapping_add(1);
        if size == 0 {
            return Ok(PciBar::NotPresent);
        }

        validate_io_port(port, size)?;

        Ok(PciBar::Io { port, size })
    } else {
        let prefetchable = (original & BAR_MEMORY_PREFETCHABLE) != 0;
        let mem_type = (original & BAR_MEMORY_TYPE_MASK) >> 1;
        match mem_type {
            0 => {
                let address = (original & BAR_MEMORY_ADDR_MASK) as u64;
                let size_bits = size_mask & BAR_MEMORY_ADDR_MASK;
                let size = ((!size_bits) as u64).wrapping_add(1) & 0xFFFF_FFFF;

                if size == 0 {
                    return Ok(PciBar::NotPresent);
                }

                validate_mmio_address(address, size)?;

                Ok(PciBar::Memory32 {
                    address: PhysAddr::new(address),
                    size,
                    prefetchable,
                })
            }
            2 => {
                if index >= 5 {
                    return Err(PciError::InvalidBarIndex(index));
                }

                let offset_hi = offset + 4;
                let original_hi = read32_unchecked(bus, device, function, offset_hi);

                write32_unchecked(bus, device, function, offset_hi, 0xFFFF_FFFF);
                let size_mask_hi = read32_unchecked(bus, device, function, offset_hi);
                write32_unchecked(bus, device, function, offset_hi, original_hi);

                let address_lo = (original & BAR_MEMORY_ADDR_MASK) as u64;
                let address_hi = original_hi as u64;
                let address = address_lo | (address_hi << 32);
                let size_lo = (size_mask & BAR_MEMORY_ADDR_MASK) as u64;
                let size_hi = size_mask_hi as u64;
                let size_combined = size_lo | (size_hi << 32);
                let size = (!size_combined).wrapping_add(1);

                if size == 0 {
                    return Ok(PciBar::NotPresent);
                }

                validate_mmio_address(address, size)?;

                Ok(PciBar::Memory64 {
                    address: PhysAddr::new(address),
                    size,
                    prefetchable,
                })
            }
            1 => Ok(PciBar::NotPresent),
            _ => Ok(PciBar::NotPresent),
        }
    }
}

pub fn decode_bar_unchecked(bus: u8, device: u8, function: u8, index: u8) -> PciBar {
    if index > 5 {
        return PciBar::NotPresent;
    }

    let offset = (CFG_BAR0 + (index as u16 * 4)) as u8;
    let original = read32_unchecked(bus, device, function, offset);

    if original == 0 || original == 0xFFFF_FFFF {
        return PciBar::NotPresent;
    }

    write32_unchecked(bus, device, function, offset, 0xFFFF_FFFF);
    let size_mask = read32_unchecked(bus, device, function, offset);
    write32_unchecked(bus, device, function, offset, original);

    if size_mask == 0 || size_mask == 0xFFFF_FFFF {
        return PciBar::NotPresent;
    }

    if (original & BAR_TYPE_MASK) == BAR_TYPE_IO {
        let port = (original & BAR_IO_ADDR_MASK) as u16;
        let size_bits = size_mask & BAR_IO_ADDR_MASK;
        let size = (!size_bits).wrapping_add(1);
        if size == 0 || port == 0 {
            return PciBar::NotPresent;
        }

        PciBar::Io { port, size }
    } else {
        let prefetchable = (original & BAR_MEMORY_PREFETCHABLE) != 0;
        let mem_type = (original & BAR_MEMORY_TYPE_MASK) >> 1;
        match mem_type {
            0 => {
                let address = (original & BAR_MEMORY_ADDR_MASK) as u64;
                let size_bits = size_mask & BAR_MEMORY_ADDR_MASK;
                let size = ((!size_bits) as u64).wrapping_add(1) & 0xFFFF_FFFF;
                if size == 0 || address == 0 {
                    return PciBar::NotPresent;
                }

                PciBar::Memory32 {
                    address: PhysAddr::new(address),
                    size,
                    prefetchable,
                }
            }
            2 => {
                if index >= 5 {
                    return PciBar::NotPresent;
                }

                let offset_hi = offset + 4;
                let original_hi = read32_unchecked(bus, device, function, offset_hi);

                write32_unchecked(bus, device, function, offset_hi, 0xFFFF_FFFF);
                let size_mask_hi = read32_unchecked(bus, device, function, offset_hi);
                write32_unchecked(bus, device, function, offset_hi, original_hi);

                let address_lo = (original & BAR_MEMORY_ADDR_MASK) as u64;
                let address_hi = original_hi as u64;
                let address = address_lo | (address_hi << 32);
                let size_lo = (size_mask & BAR_MEMORY_ADDR_MASK) as u64;
                let size_hi = size_mask_hi as u64;
                let size_combined = size_lo | (size_hi << 32);
                let size = (!size_combined).wrapping_add(1);
                if size == 0 || address == 0 {
                    return PciBar::NotPresent;
                }

                PciBar::Memory64 {
                    address: PhysAddr::new(address),
                    size,
                    prefetchable,
                }
            }
            _ => PciBar::NotPresent,
        }
    }
}

pub fn decode_all_bars(bus: u8, device: u8, function: u8) -> [PciBar; 6] {
    let mut bars = [PciBar::NotPresent; 6];
    let mut index = 0u8;
    while index < 6 {
        match decode_bar(bus, device, function, index) {
            Ok(bar) => {
                let skip = bar.is_64bit();
                bars[index as usize] = bar;
                index += if skip { 2 } else { 1 };
            }
            Err(_) => {
                index += 1;
            }
        }
    }

    bars
}

pub fn decode_all_bars_unchecked(bus: u8, device: u8, function: u8) -> [PciBar; 6] {
    let mut bars = [PciBar::NotPresent; 6];
    let mut index = 0u8;

    while index < 6 {
        let bar = decode_bar_unchecked(bus, device, function, index);
        let skip = bar.is_64bit();
        bars[index as usize] = bar;
        index += if skip { 2 } else { 1 };
    }

    bars
}

pub fn bar_type(bar: &PciBar) -> BarType {
    match bar {
        PciBar::Memory32 { .. } => BarType::Memory32,
        PciBar::Memory64 { .. } => BarType::Memory64,
        PciBar::Memory { is_64bit: true, .. } => BarType::Memory64,
        PciBar::Memory { is_64bit: false, .. } => BarType::Memory32,
        PciBar::Io { .. } => BarType::Io,
        PciBar::NotPresent => BarType::NotPresent,
    }
}

pub struct BarInfo {
    pub bar: PciBar,
    pub index: u8,
    pub consumes_two_slots: bool,
}

impl BarInfo {
    pub fn from_bar(bar: PciBar, index: u8) -> Self {
        Self {
            consumes_two_slots: bar.is_64bit(),
            bar,
            index,
        }
    }

    pub fn next_index(&self) -> u8 {
        if self.consumes_two_slots {
            self.index + 2
        } else {
            self.index + 1
        }
    }
}

pub fn enumerate_bars(bus: u8, device: u8, function: u8) -> impl Iterator<Item = BarInfo> {
    let bars = decode_all_bars(bus, device, function);

    BarIterator {
        bars,
        current_index: 0,
    }
}

struct BarIterator {
    bars: [PciBar; 6],
    current_index: u8,
}

impl Iterator for BarIterator {
    type Item = BarInfo;
    fn next(&mut self) -> Option<Self::Item> {
        while self.current_index < 6 {
            let index = self.current_index;
            let bar = self.bars[index as usize];
            if bar.is_present() {
                let info = BarInfo::from_bar(bar, index);
                self.current_index = info.next_index();
                return Some(info);
            }

            self.current_index += 1;
        }

        None
    }
}

pub fn calculate_bar_alignment(size: u64) -> u64 {
    if size == 0 {
        return 0;
    }

    let mut alignment = 1u64;
    while alignment < size {
        alignment <<= 1;
    }
    alignment
}

pub fn is_bar_address_valid(bar: &PciBar) -> bool {
    match bar {
        PciBar::Memory32 { address, size, .. } => {
            validate_mmio_address(address.as_u64(), *size).is_ok()
        }
        PciBar::Memory64 { address, size, .. } => {
            validate_mmio_address(address.as_u64(), *size).is_ok()
        }
        PciBar::Memory { address, size, .. } => {
            validate_mmio_address(address.as_u64(), *size as u64).is_ok()
        }
        PciBar::Io { port, size } => validate_io_port(*port, *size).is_ok(),
        PciBar::NotPresent => true,
    }
}
