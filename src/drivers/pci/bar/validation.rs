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
use super::super::error::{PciError, ProtectedRegion, Result};

pub(super) fn validate_mmio_address(address: u64, size: u64) -> Result<()> {
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
        return Err(PciError::BarTooLarge {
            size,
            max: MAX_BAR_SIZE,
        });
    }

    if is_protected_region(address, size) {
        let region = identify_protected_region(address);
        return Err(PciError::BarOverlapsProtected { address, region });
    }

    Ok(())
}

pub(super) fn is_protected_region(address: u64, size: u64) -> bool {
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

pub(super) fn identify_protected_region(address: u64) -> ProtectedRegion {
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

pub(super) fn validate_io_port(port: u16, size: u32) -> Result<()> {
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
