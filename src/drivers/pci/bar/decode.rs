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

use x86_64::PhysAddr;

use super::super::config::{read32_unchecked, write32_unchecked};
use super::super::constants::*;
use super::super::error::{PciError, Result};
use super::super::types::PciBar;
use super::validation::{validate_io_port, validate_mmio_address};

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
